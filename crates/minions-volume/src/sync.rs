//! Background sync engine for flushing dirty blocks to S3
//!
//! Periodically scans for dirty blocks, groups them by segment, and uploads to S3.
//! Supports forced flush and graceful shutdown.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::cache::BlockCache;
use crate::s3::S3Backend;
use crate::{lba_to_segment, Lba, SegmentId, BLOCK_SIZE, BLOCKS_PER_SEGMENT, SEGMENT_SIZE};

/// Sync engine configuration
#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub volume_name: String,
    pub sync_interval_secs: u64,
}

impl SyncConfig {
    /// Load from environment
    pub fn from_env(volume_name: String) -> Self {
        let sync_interval_secs = std::env::var("MINIONS_VOLUME_SYNC_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        SyncConfig {
            volume_name,
            sync_interval_secs,
        }
    }
}

/// Sync engine statistics
#[derive(Debug, Default)]
pub struct SyncStats {
    pub syncs_completed: AtomicU64,
    pub blocks_synced: AtomicU64,
    pub bytes_synced: AtomicU64,
    pub sync_errors: AtomicU64,
}

impl SyncStats {
    pub fn new() -> Arc<Self> {
        Arc::new(SyncStats::default())
    }

    pub fn record_sync(&self, blocks: u64, bytes: u64) {
        self.syncs_completed.fetch_add(1, Ordering::Relaxed);
        self.blocks_synced.fetch_add(blocks, Ordering::Relaxed);
        self.bytes_synced.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.sync_errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// Background sync engine
pub struct SyncEngine {
    config: SyncConfig,
    cache: Arc<BlockCache>,
    s3_backend: Arc<S3Backend>,
    shutdown: Arc<AtomicBool>,
    force_sync: Arc<Notify>,
    stats: Arc<SyncStats>,
}

impl SyncEngine {
    /// Create a new sync engine
    pub fn new(
        config: SyncConfig,
        cache: Arc<BlockCache>,
        s3_backend: Arc<S3Backend>,
    ) -> Self {
        SyncEngine {
            config,
            cache,
            s3_backend,
            shutdown: Arc::new(AtomicBool::new(false)),
            force_sync: Arc::new(Notify::new()),
            stats: SyncStats::new(),
        }
    }

    /// Start the sync engine (runs in background)
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<Result<()>> {
        let engine = self.clone();
        tokio::spawn(async move { engine.run().await })
    }

    /// Request an immediate sync
    pub fn trigger_sync(&self) {
        self.force_sync.notify_one();
    }

    /// Perform a sync and wait for completion
    pub async fn sync_now(&self) -> Result<()> {
        self.do_sync().await
    }

    /// Request shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.force_sync.notify_one();
    }

    /// Get statistics
    pub fn stats(&self) -> Arc<SyncStats> {
        self.stats.clone()
    }

    /// Main sync loop
    async fn run(self: Arc<Self>) -> Result<()> {
        info!(
            "Sync engine started (interval: {}s)",
            self.config.sync_interval_secs
        );

        let mut ticker = interval(Duration::from_secs(self.config.sync_interval_secs));

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    // Periodic sync
                    if let Err(e) = self.do_sync().await {
                        error!("Periodic sync failed: {}", e);
                        self.stats.record_error();
                    }
                }
                _ = self.force_sync.notified() => {
                    // Forced sync
                    debug!("Forced sync requested");
                    if let Err(e) = self.do_sync().await {
                        error!("Forced sync failed: {}", e);
                        self.stats.record_error();
                    }
                }
            }

            if self.shutdown.load(Ordering::Relaxed) {
                info!("Sync engine shutting down");
                // Final sync before shutdown
                if let Err(e) = self.do_sync().await {
                    error!("Final sync failed: {}", e);
                }
                break;
            }
        }

        Ok(())
    }

    /// Perform a sync operation
    async fn do_sync(&self) -> Result<()> {
        let dirty_blocks = self.cache.dirty_blocks();

        if dirty_blocks.is_empty() {
            return Ok(());
        }

        info!("Syncing {} dirty blocks to S3", dirty_blocks.len());

        // Group blocks by segment
        let segments = self.group_by_segment(&dirty_blocks);

        let mut total_blocks = 0;
        let mut total_bytes = 0;

        // Sync each segment
        for (segment_id, block_offsets) in segments {
            match self.sync_segment(segment_id, &block_offsets).await {
                Ok(_) => {
                    total_blocks += block_offsets.len();
                    total_bytes += block_offsets.len() * BLOCK_SIZE;

                    // Mark blocks as clean
                    for &offset in &block_offsets {
                        let lba = crate::segment_to_lba(segment_id, offset);
                        if let Err(e) = self.cache.mark_clean(lba) {
                            warn!("Failed to mark block {} clean: {}", lba, e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to sync segment {}: {}", segment_id, e);
                    self.stats.record_error();
                    // Continue with other segments
                }
            }
        }

        if total_blocks > 0 {
            self.stats.record_sync(total_blocks as u64, total_bytes as u64);
            info!(
                "Sync complete: {} blocks ({} MB)",
                total_blocks,
                total_bytes / (1024 * 1024)
            );
        }

        // Flush bitmaps
        self.cache.flush_bitmaps()
            .context("Failed to flush cache bitmaps")?;

        Ok(())
    }

    /// Group dirty blocks by segment
    fn group_by_segment(&self, dirty_blocks: &[Lba]) -> HashMap<SegmentId, Vec<usize>> {
        let mut segments: HashMap<SegmentId, Vec<usize>> = HashMap::new();

        for &lba in dirty_blocks {
            let (segment_id, block_offset) = lba_to_segment(lba);
            segments
                .entry(segment_id)
                .or_insert_with(Vec::new)
                .push(block_offset);
        }

        segments
    }

    /// Sync a single segment to S3
    async fn sync_segment(&self, segment_id: SegmentId, block_offsets: &[usize]) -> Result<()> {
        debug!(
            "Syncing segment {} ({} dirty blocks)",
            segment_id,
            block_offsets.len()
        );

        // Read or initialize segment buffer
        let mut segment_data = self.read_or_create_segment(segment_id).await?;

        // Update dirty blocks in segment buffer
        for &block_offset in block_offsets {
            let lba = crate::segment_to_lba(segment_id, block_offset);
            
            match self.cache.read_block(lba)? {
                Some(block_data) => {
                    let seg_offset = block_offset * BLOCK_SIZE;
                    segment_data[seg_offset..seg_offset + BLOCK_SIZE].copy_from_slice(&block_data);
                }
                None => {
                    warn!("Block {} marked dirty but not present in cache", lba);
                }
            }
        }

        // Upload segment to S3
        self.s3_backend
            .write_segment(&self.config.volume_name, segment_id, &segment_data)
            .await
            .context("Failed to upload segment to S3")?;

        debug!("Segment {} synced successfully", segment_id);
        Ok(())
    }

    /// Read existing segment from S3 or create a new empty one
    async fn read_or_create_segment(&self, segment_id: SegmentId) -> Result<Vec<u8>> {
        match self
            .s3_backend
            .read_segment(&self.config.volume_name, segment_id)
            .await
        {
            Ok(data) => Ok(data),
            Err(_) => {
                // Segment doesn't exist yet, create empty
                debug!("Creating new segment {}", segment_id);
                Ok(vec![0u8; SEGMENT_SIZE])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_by_segment() {
        use crate::segment_to_lba;

        // Create some test LBAs spanning multiple segments
        let dirty_blocks = vec![
            segment_to_lba(0, 0),
            segment_to_lba(0, 1),
            segment_to_lba(0, 100),
            segment_to_lba(1, 0),
            segment_to_lba(1, 500),
            segment_to_lba(5, 0),
        ];

        let cache = Arc::new(
            BlockCache::open(crate::cache::CacheConfig {
                cache_dir: std::env::temp_dir(),
                volume_name: "test".to_string(),
                volume_size: 100 * 1024 * 1024,
                max_cache_bytes: None,
            })
            .unwrap(),
        );

        let s3_backend = Arc::new(
            S3Backend::new(crate::s3::S3Config {
                endpoint: "http://localhost:9000".to_string(),
                region: "us-east-1".to_string(),
                bucket: "test".to_string(),
                access_key: "test".to_string(),
                secret_key: "test".to_string(),
                path_style: true,
            })
            .unwrap(),
        );

        let engine = SyncEngine::new(
            SyncConfig {
                volume_name: "test".to_string(),
                sync_interval_secs: 30,
            },
            cache,
            s3_backend,
        );

        let segments = engine.group_by_segment(&dirty_blocks);

        assert_eq!(segments.len(), 3);
        assert_eq!(segments.get(&0).unwrap().len(), 3);
        assert_eq!(segments.get(&1).unwrap().len(), 2);
        assert_eq!(segments.get(&5).unwrap().len(), 1);
    }
}
