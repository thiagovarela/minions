//! Volume manager - orchestrates NBD server, cache, S3, and sync
//!
//! Provides high-level API for volume lifecycle management.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::cache::{BlockCache, CacheConfig};
use crate::nbd::{NbdCommandHandler, NbdServer, NbdServerConfig};
use crate::s3::{S3Backend, S3Config};
use crate::sync::{SyncConfig, SyncEngine};
use crate::{Lba, VolumeSize, BLOCK_SIZE};

/// Volume configuration
#[derive(Debug, Clone)]
pub struct VolumeConfig {
    pub name: String,
    pub size: VolumeSize,
    pub s3_config: S3Config,
    pub cache_config: Option<CacheConfig>,
    pub sync_config: Option<SyncConfig>,
    pub socket_path: Option<PathBuf>,
    pub read_only: bool,
}

impl VolumeConfig {
    /// Create a new volume configuration
    pub fn new(name: String, size: VolumeSize, s3_config: S3Config) -> Self {
        VolumeConfig {
            name,
            size,
            s3_config,
            cache_config: None,
            sync_config: None,
            socket_path: None,
            read_only: false,
        }
    }

    /// Set cache configuration
    pub fn with_cache_config(mut self, config: CacheConfig) -> Self {
        self.cache_config = Some(config);
        self
    }

    /// Set sync configuration
    pub fn with_sync_config(mut self, config: SyncConfig) -> Self {
        self.sync_config = Some(config);
        self
    }

    /// Set socket path
    pub fn with_socket_path(mut self, path: PathBuf) -> Self {
        self.socket_path = Some(path);
        self
    }

    /// Set read-only mode
    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }
}

/// Volume handle - represents an active volume
pub struct VolumeHandle {
    config: VolumeConfig,
    cache: Arc<BlockCache>,
    s3_backend: Arc<S3Backend>,
    sync_engine: Arc<SyncEngine>,
    sync_task: Option<JoinHandle<Result<()>>>,
    nbd_task: Option<JoinHandle<()>>,
    socket_path: PathBuf,
}

impl VolumeHandle {
    /// Create a new volume in S3
    pub async fn create(config: VolumeConfig) -> Result<()> {
        info!("Creating volume '{}' with size {} bytes", config.name, config.size);

        let s3_backend = S3Backend::new(config.s3_config.clone())?;
        s3_backend.create_volume(&config.name, config.size).await?;

        info!("Volume '{}' created successfully", config.name);
        Ok(())
    }

    /// Open an existing volume and start NBD server
    pub async fn open(config: VolumeConfig) -> Result<Self> {
        info!("Opening volume '{}'", config.name);

        // Initialize S3 backend
        let s3_backend = Arc::new(S3Backend::new(config.s3_config.clone())?);

        // Verify volume exists
        let metadata = s3_backend.get_volume_metadata(&config.name).await?;
        info!("Volume metadata: size={} bytes", metadata.size_bytes);

        // Initialize cache
        let cache_config = config.cache_config.clone().unwrap_or_else(|| {
            CacheConfig::from_env(config.name.clone(), metadata.size_bytes)
        });
        let cache = Arc::new(BlockCache::open(cache_config)?);

        // Initialize sync engine
        let sync_config = config.sync_config.clone().unwrap_or_else(|| {
            SyncConfig::from_env(config.name.clone())
        });
        let sync_engine = Arc::new(SyncEngine::new(
            sync_config,
            cache.clone(),
            s3_backend.clone(),
        ));

        // Start sync engine
        let sync_task = Some(sync_engine.clone().start());

        // Determine socket path
        let socket_path = config.socket_path.clone().unwrap_or_else(|| {
            PathBuf::from(format!("/var/lib/minions/nbd/{}.sock", config.name))
        });

        // Create and start NBD server
        let nbd_config = NbdServerConfig {
            socket_path: socket_path.clone(),
            export_name: config.name.clone(),
            export_size: metadata.size_bytes,
            read_only: config.read_only,
        };

        let mut nbd_server = NbdServer::new(nbd_config)?;
        nbd_server.start().await?;

        // Spawn task to accept NBD connections on the started server
        let volume_name = config.name.clone();
        let cache_clone = cache.clone();
        let s3_clone = s3_backend.clone();
        let nbd_task = tokio::spawn(async move {
            let mut server = nbd_server;
            loop {
                let handler = VolumeCommandHandler {
                    cache: cache_clone.clone(),
                    s3_backend: s3_clone.clone(),
                    volume_name: volume_name.clone(),
                };

                match server.accept_and_handle(handler).await {
                    Ok(_) => info!("NBD client disconnected"),
                    Err(e) => {
                        warn!("NBD client error: {}", e);
                        // Brief backoff to avoid busy loop on persistent errors
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                }
            }
        });

        info!("Volume '{}' opened successfully", config.name);

        Ok(VolumeHandle {
            config,
            cache,
            s3_backend,
            sync_engine,
            sync_task,
            nbd_task: Some(nbd_task),
            socket_path,
        })
    }

    /// Get the NBD socket path
    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    /// Get volume name
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get volume size
    pub fn size(&self) -> VolumeSize {
        self.config.size
    }

    /// Trigger an immediate sync
    pub fn trigger_sync(&self) {
        self.sync_engine.trigger_sync();
    }

    /// Perform a sync and wait for completion
    pub async fn sync_now(&self) -> Result<()> {
        self.sync_engine.sync_now().await
    }

    /// Flush all pending writes
    pub async fn flush(&self) -> Result<()> {
        info!("Flushing volume '{}'", self.config.name);
        
        // Sync to S3
        self.sync_now().await?;
        
        // Flush cache
        self.cache.flush()?;

        info!("Volume '{}' flushed successfully", self.config.name);
        Ok(())
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize, u64) {
        (
            self.cache.dirty_count(),
            self.cache.present_count(),
            self.cache.cache_size_bytes(),
        )
    }

    /// Close the volume
    pub async fn close(mut self) -> Result<()> {
        info!("Closing volume '{}'", self.config.name);

        // Flush all pending writes
        self.flush().await?;

        // Shutdown sync engine
        self.sync_engine.shutdown();
        if let Some(task) = self.sync_task.take() {
            let _ = task.await;
        }

        // Stop NBD accept loop
        if let Some(task) = self.nbd_task.take() {
            task.abort();
        }

        info!("Volume '{}' closed successfully", self.config.name);
        Ok(())
    }

    /// Destroy the volume (delete from S3)
    pub async fn destroy(volume_name: &str, s3_config: S3Config) -> Result<()> {
        info!("Destroying volume '{}'", volume_name);

        let s3_backend = S3Backend::new(s3_config)?;
        s3_backend.delete_volume(volume_name).await?;

        // Delete local cache
        let cache_config = CacheConfig::from_env(volume_name.to_string(), 0);
        let cache_dir = cache_config.cache_dir.join(volume_name);
        if cache_dir.exists() {
            std::fs::remove_dir_all(&cache_dir)
                .context("Failed to remove cache directory")?;
        }

        info!("Volume '{}' destroyed successfully", volume_name);
        Ok(())
    }
}

/// NBD command handler implementation
struct VolumeCommandHandler {
    cache: Arc<BlockCache>,
    s3_backend: Arc<S3Backend>,
    volume_name: String,
}

#[async_trait::async_trait]
impl NbdCommandHandler for VolumeCommandHandler {
    async fn read(&self, offset: u64, length: u32) -> Result<Vec<u8>> {
        if length == 0 {
            return Ok(Vec::new());
        }

        // Convert offset to LBA
        let start_lba = offset / BLOCK_SIZE as u64;
        let end_lba = (offset + length as u64 + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64;

        let mut result = Vec::with_capacity(length as usize);

        for lba in start_lba..end_lba {
            let block_data = match self.cache.read_block(lba)? {
                Some(data) => data,
                None => {
                    // Block not in cache, fetch from S3
                    self.fetch_block_from_s3(lba).await?
                }
            };

            // Calculate which portion of this block to include
            let block_start = lba * BLOCK_SIZE as u64;
            let block_end = block_start + BLOCK_SIZE as u64;
            
            let copy_start = if block_start < offset {
                (offset - block_start) as usize
            } else {
                0
            };
            
            let copy_end = if block_end > offset + length as u64 {
                BLOCK_SIZE - (block_end - offset - length as u64) as usize
            } else {
                BLOCK_SIZE
            };

            result.extend_from_slice(&block_data[copy_start..copy_end]);
        }

        Ok(result)
    }

    async fn write(&self, offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        // Convert offset to LBA
        let start_lba = offset / BLOCK_SIZE as u64;
        let end_lba = (offset + data.len() as u64 + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64;

        let mut data_offset = 0;

        for lba in start_lba..end_lba {
            let block_start = lba * BLOCK_SIZE as u64;
            let block_end = block_start + BLOCK_SIZE as u64;

            // Check if we're writing a full block or partial
            let write_start = if block_start < offset {
                (offset - block_start) as usize
            } else {
                0
            };

            let write_end = if block_end > offset + data.len() as u64 {
                BLOCK_SIZE - (block_end - offset - data.len() as u64) as usize
            } else {
                BLOCK_SIZE
            };

            let mut block_data = if write_start == 0 && write_end == BLOCK_SIZE {
                // Full block write
                vec![0u8; BLOCK_SIZE]
            } else {
                // Partial write, need to read-modify-write
                match self.cache.read_block(lba)? {
                    Some(data) => data,
                    None => self.fetch_block_from_s3(lba).await?,
                }
            };

            // Copy data into block
            let write_len = write_end - write_start;
            block_data[write_start..write_end]
                .copy_from_slice(&data[data_offset..data_offset + write_len]);
            data_offset += write_len;

            // Write to cache
            self.cache.write_block(lba, &block_data)?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        self.cache.flush()?;
        Ok(())
    }

    async fn trim(&self, _offset: u64, _length: u32) -> Result<()> {
        // TRIM/discard is optional - could mark blocks as unused
        // For now, just acknowledge
        Ok(())
    }
}

impl VolumeCommandHandler {
    /// Fetch a block from S3 and populate cache
    async fn fetch_block_from_s3(&self, lba: Lba) -> Result<Vec<u8>> {
        let (segment_id, block_offset) = crate::lba_to_segment(lba);

        // Fetch entire segment from S3.
        // If the segment does not exist yet, treat it as zero-filled.
        let segment_data = match self
            .s3_backend
            .segment_exists(&self.volume_name, segment_id)
            .await
        {
            Ok(true) => match self
                .s3_backend
                .read_segment(&self.volume_name, segment_id)
                .await
            {
                Ok(data) => data,
                Err(e) => {
                    tracing::warn!(
                        "Segment {} read failed for volume '{}', using zero-filled segment: {}",
                        segment_id,
                        self.volume_name,
                        e
                    );
                    vec![0u8; crate::SEGMENT_SIZE]
                }
            },
            Ok(false) => vec![0u8; crate::SEGMENT_SIZE],
            Err(e) => {
                tracing::warn!(
                    "Segment {} existence check failed for volume '{}', using zero-filled segment: {}",
                    segment_id,
                    self.volume_name,
                    e
                );
                vec![0u8; crate::SEGMENT_SIZE]
            }
        };

        // Extract the requested block
        let block_start = block_offset * BLOCK_SIZE;
        let block_end = block_start + BLOCK_SIZE;
        let block_data = segment_data[block_start..block_end].to_vec();

        // Cache all blocks from this segment
        for i in 0..crate::BLOCKS_PER_SEGMENT {
            let block_lba = crate::segment_to_lba(segment_id, i);
            let start = i * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            
            // Only cache if not already present
            if !self.cache.is_present(block_lba) {
                self.cache.write_block(block_lba, &segment_data[start..end])?;
                self.cache.mark_clean(block_lba)?;
                self.cache.mark_present(block_lba)?;
            }
        }

        Ok(block_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volume_config() {
        let s3_config = S3Config {
            endpoint: "http://localhost:9000".to_string(),
            region: "us-east-1".to_string(),
            bucket: "test".to_string(),
            access_key: "test".to_string(),
            secret_key: "test".to_string(),
            path_style: true,
        };

        let config = VolumeConfig::new("test-vol".to_string(), 10 * 1024 * 1024, s3_config)
            .with_read_only(true);

        assert_eq!(config.name, "test-vol");
        assert_eq!(config.size, 10 * 1024 * 1024);
        assert!(config.read_only);
    }
}
