//! S3 storage backend for volume segments
//!
//! Manages volume data storage in S3-compatible object storage.
//! Volumes are stored as:
//! - meta.json: Volume metadata (size, created timestamp)
//! - segments/{seg_id}.bin: 4MB data segments

use anyhow::{bail, Context, Result};
use s3::creds::Credentials;
use s3::{Bucket, Region};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info};

use crate::{SegmentId, VolumeSize, SEGMENT_SIZE};

/// S3 configuration
#[derive(Debug, Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
}

impl S3Config {
    /// Load from environment variables
    pub fn from_env() -> Result<Self> {
        Ok(S3Config {
            endpoint: std::env::var("MINIONS_S3_ENDPOINT")
                .unwrap_or_else(|_| "https://s3.amazonaws.com".to_string()),
            region: std::env::var("MINIONS_S3_REGION")
                .unwrap_or_else(|_| "us-east-1".to_string()),
            bucket: std::env::var("MINIONS_S3_BUCKET")
                .context("MINIONS_S3_BUCKET not set")?,
            access_key: std::env::var("MINIONS_S3_ACCESS_KEY")
                .context("MINIONS_S3_ACCESS_KEY not set")?,
            secret_key: std::env::var("MINIONS_S3_SECRET_KEY")
                .context("MINIONS_S3_SECRET_KEY not set")?,
        })
    }
}

/// Volume metadata stored in S3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMetadata {
    pub name: String,
    pub size_bytes: u64,
    pub block_size: usize,
    pub segment_size: usize,
    pub created_at: String,
}

/// S3 storage backend
pub struct S3Backend {
    bucket: Arc<Bucket>,
    volume_prefix: String,
}

impl S3Backend {
    /// Create a new S3 backend
    pub fn new(config: S3Config) -> Result<Self> {
        let credentials = Credentials::new(
            Some(&config.access_key),
            Some(&config.secret_key),
            None,
            None,
            None,
        )
        .context("Failed to create S3 credentials")?;

        // Parse region and endpoint
        let region = if config.endpoint.starts_with("http://") || config.endpoint.starts_with("https://") {
            Region::Custom {
                region: config.region.clone(),
                endpoint: config.endpoint.clone(),
            }
        } else {
            config.region.parse()
                .context("Invalid AWS region")?
        };

        let bucket = Bucket::new(&config.bucket, region, credentials)
            .context("Failed to create S3 bucket")?
            .with_path_style(); // Use path-style for MinIO compatibility

        info!("Initialized S3 backend: bucket={}", config.bucket);

        Ok(S3Backend {
            bucket: Arc::new(*bucket),
            volume_prefix: "volumes".to_string(),
        })
    }

    /// Create a new volume
    pub async fn create_volume(&self, name: &str, size_bytes: u64) -> Result<()> {
        info!("Creating volume '{}' with size {} bytes", name, size_bytes);

        // Check if volume already exists
        if self.volume_exists(name).await? {
            bail!("Volume '{}' already exists", name);
        }

        // Create metadata
        let metadata = VolumeMetadata {
            name: name.to_string(),
            size_bytes,
            block_size: crate::BLOCK_SIZE,
            segment_size: SEGMENT_SIZE,
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        let meta_json = serde_json::to_string_pretty(&metadata)?;
        let meta_path = self.volume_meta_path(name);

        // Upload metadata
        self.bucket
            .put_object(&meta_path, meta_json.as_bytes())
            .await
            .context("Failed to upload volume metadata")?;

        info!("Volume '{}' created successfully", name);
        Ok(())
    }

    /// Check if a volume exists
    pub async fn volume_exists(&self, name: &str) -> Result<bool> {
        let meta_path = self.volume_meta_path(name);
        
        match self.bucket.head_object(&meta_path).await {
            Ok(_) => Ok(true),
            Err(s3::error::S3Error::HttpFailWithBody(404, _)) => Ok(false),
            Err(e) => Err(e).context("Failed to check volume existence"),
        }
    }

    /// Get volume metadata
    pub async fn get_volume_metadata(&self, name: &str) -> Result<VolumeMetadata> {
        let meta_path = self.volume_meta_path(name);
        
        let response = self.bucket
            .get_object(&meta_path)
            .await
            .context("Failed to get volume metadata")?;

        let metadata: VolumeMetadata = serde_json::from_slice(response.bytes())
            .context("Failed to parse volume metadata")?;

        Ok(metadata)
    }

    /// Write a segment to S3
    pub async fn write_segment(&self, name: &str, segment_id: SegmentId, data: &[u8]) -> Result<()> {
        if data.len() != SEGMENT_SIZE {
            bail!("Invalid segment size: {} (expected {})", data.len(), SEGMENT_SIZE);
        }

        let segment_path = self.segment_path(name, segment_id);
        debug!("Writing segment {} to S3 ({})", segment_id, segment_path);

        self.bucket
            .put_object(&segment_path, data)
            .await
            .context("Failed to upload segment")?;

        Ok(())
    }

    /// Read a segment from S3
    pub async fn read_segment(&self, name: &str, segment_id: SegmentId) -> Result<Vec<u8>> {
        let segment_path = self.segment_path(name, segment_id);
        debug!("Reading segment {} from S3 ({})", segment_id, segment_path);

        let response = self.bucket
            .get_object(&segment_path)
            .await
            .context("Failed to download segment")?;

        let data = response.bytes().to_vec();
        
        if data.len() != SEGMENT_SIZE {
            bail!("Segment {} has invalid size: {} (expected {})", 
                  segment_id, data.len(), SEGMENT_SIZE);
        }

        Ok(data)
    }

    /// Check if a segment exists
    pub async fn segment_exists(&self, name: &str, segment_id: SegmentId) -> Result<bool> {
        let segment_path = self.segment_path(name, segment_id);
        
        match self.bucket.head_object(&segment_path).await {
            Ok(_) => Ok(true),
            Err(s3::error::S3Error::HttpFailWithBody(404, _)) => Ok(false),
            Err(e) => Err(e).context("Failed to check segment existence"),
        }
    }

    /// Delete a segment
    pub async fn delete_segment(&self, name: &str, segment_id: SegmentId) -> Result<()> {
        let segment_path = self.segment_path(name, segment_id);
        debug!("Deleting segment {} from S3", segment_id);

        self.bucket
            .delete_object(&segment_path)
            .await
            .context("Failed to delete segment")?;

        Ok(())
    }

    /// List all segments for a volume
    pub async fn list_segments(&self, name: &str) -> Result<Vec<SegmentId>> {
        let segments_prefix = format!("{}/{}/segments/", self.volume_prefix, name);
        
        let results = self.bucket
            .list(segments_prefix.clone(), None)
            .await
            .context("Failed to list segments")?;

        let mut segment_ids = Vec::new();

        for result in results {
            for object in result.contents {
                // Extract segment ID from path: volumes/{name}/segments/{id}.bin
                if let Some(filename) = object.key.strip_prefix(&segments_prefix) {
                    if let Some(id_str) = filename.strip_suffix(".bin") {
                        if let Ok(id) = id_str.parse::<SegmentId>() {
                            segment_ids.push(id);
                        }
                    }
                }
            }
        }

        segment_ids.sort();
        Ok(segment_ids)
    }

    /// Delete a volume and all its segments
    pub async fn delete_volume(&self, name: &str) -> Result<()> {
        info!("Deleting volume '{}'", name);

        let volume_prefix = format!("{}/{}/", self.volume_prefix, name);
        
        // List all objects with this prefix
        let results = self.bucket
            .list(volume_prefix.clone(), None)
            .await
            .context("Failed to list volume objects")?;

        // Delete all objects
        let mut delete_count = 0;
        for result in results {
            for object in result.contents {
                self.bucket
                    .delete_object(&object.key)
                    .await
                    .context("Failed to delete object")?;
                delete_count += 1;
            }
        }

        info!("Deleted volume '{}' ({} objects)", name, delete_count);
        Ok(())
    }

    /// List all volumes
    pub async fn list_volumes(&self) -> Result<Vec<String>> {
        let prefix = format!("{}/", self.volume_prefix);
        
        let results = self.bucket
            .list(prefix.clone(), Some("/".to_string()))
            .await
            .context("Failed to list volumes")?;

        let mut volume_names = Vec::new();

        for result in results {
            for common_prefix in result.common_prefixes.unwrap_or_default() {
                // Extract volume name from prefix: volumes/{name}/
                if let Some(name) = common_prefix.prefix.strip_prefix(&prefix) {
                    if let Some(name) = name.strip_suffix('/') {
                        volume_names.push(name.to_string());
                    }
                }
            }
        }

        volume_names.sort();
        Ok(volume_names)
    }

    /// Get volume metadata path
    fn volume_meta_path(&self, name: &str) -> String {
        format!("{}/{}/meta.json", self.volume_prefix, name)
    }

    /// Get segment path
    fn segment_path(&self, name: &str, segment_id: SegmentId) -> String {
        format!("{}/{}/segments/{}.bin", self.volume_prefix, name, segment_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_generation() {
        let config = S3Config {
            endpoint: "http://localhost:9000".to_string(),
            region: "us-east-1".to_string(),
            bucket: "test-bucket".to_string(),
            access_key: "test".to_string(),
            secret_key: "test".to_string(),
        };

        let backend = S3Backend::new(config).unwrap();
        
        assert_eq!(
            backend.volume_meta_path("myvolume"),
            "volumes/myvolume/meta.json"
        );
        
        assert_eq!(
            backend.segment_path("myvolume", 0),
            "volumes/myvolume/segments/0.bin"
        );
        
        assert_eq!(
            backend.segment_path("myvolume", 123),
            "volumes/myvolume/segments/123.bin"
        );
    }
}
