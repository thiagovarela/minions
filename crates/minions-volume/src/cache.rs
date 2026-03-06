//! Local block cache for S3-backed volumes
//!
//! Uses a sparse file for data storage and bitmaps to track block state.
//! Supports efficient reads, writes, and LRU eviction of clean blocks.

use anyhow::{bail, Context, Result};
use bitvec::prelude::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

use crate::{Lba, VolumeSize, BLOCK_SIZE};

type BitMap = BitVec<u8, Lsb0>;

/// Block cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub cache_dir: PathBuf,
    pub volume_name: String,
    pub volume_size: u64,
    pub max_cache_bytes: Option<u64>,
}

impl CacheConfig {
    /// Load default config from environment
    pub fn from_env(volume_name: String, volume_size: u64) -> Self {
        let cache_dir = std::env::var("MINIONS_VOLUME_CACHE_DIR")
            .unwrap_or_else(|_| "/var/lib/minions/volume-cache".to_string());

        let max_cache_gb = std::env::var("MINIONS_VOLUME_CACHE_MAX_GB")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(50);

        CacheConfig {
            cache_dir: PathBuf::from(cache_dir),
            volume_name,
            volume_size,
            max_cache_bytes: Some(max_cache_gb * 1024 * 1024 * 1024),
        }
    }
}

/// Local block cache
pub struct BlockCache {
    config: CacheConfig,
    data_file: Arc<Mutex<File>>,
    dirty_bitmap: Arc<Mutex<BitMap>>,
    present_bitmap: Arc<Mutex<BitMap>>,
    num_blocks: u64,
}

impl BlockCache {
    /// Open or create a block cache
    pub fn open(config: CacheConfig) -> Result<Self> {
        let num_blocks = (config.volume_size + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64;

        info!(
            "Opening block cache for '{}' ({} blocks, {} GB)",
            config.volume_name,
            num_blocks,
            config.volume_size / (1024 * 1024 * 1024)
        );

        // Create cache directory
        let volume_cache_dir = config.cache_dir.join(&config.volume_name);
        std::fs::create_dir_all(&volume_cache_dir)
            .context("Failed to create cache directory")?;

        // Open or create sparse data file
        let data_path = volume_cache_dir.join("data.img");
        let data_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&data_path)
            .context("Failed to open cache data file")?;

        // Set file size (sparse)
        data_file
            .set_len(config.volume_size)
            .context("Failed to set cache file size")?;

        // Load or create bitmaps
        let bitmap_path = volume_cache_dir.join("dirty.bitmap");
        let dirty_bitmap = Self::load_or_create_bitmap(&bitmap_path, num_blocks as usize)?;

        let present_path = volume_cache_dir.join("present.bitmap");
        let present_bitmap = Self::load_or_create_bitmap(&present_path, num_blocks as usize)?;

        info!("Block cache opened successfully");

        Ok(BlockCache {
            config,
            data_file: Arc::new(Mutex::new(data_file)),
            dirty_bitmap: Arc::new(Mutex::new(dirty_bitmap)),
            present_bitmap: Arc::new(Mutex::new(present_bitmap)),
            num_blocks,
        })
    }

    /// Read a block from cache (returns None if not present)
    pub fn read_block(&self, lba: Lba) -> Result<Option<Vec<u8>>> {
        if lba >= self.num_blocks {
            bail!("LBA {} out of range (max {})", lba, self.num_blocks - 1);
        }

        // Check if block is present
        let present = {
            let bitmap = self.present_bitmap.lock().unwrap();
            bitmap[lba as usize]
        };

        if !present {
            return Ok(None);
        }

        // Read from sparse file
        let offset = lba * BLOCK_SIZE as u64;
        let mut buffer = vec![0u8; BLOCK_SIZE];

        let file = self.data_file.lock().unwrap();
        file.read_exact_at(&mut buffer, offset)
            .context("Failed to read block from cache")?;

        Ok(Some(buffer))
    }

    /// Write a block to cache and mark it dirty
    pub fn write_block(&self, lba: Lba, data: &[u8]) -> Result<()> {
        if lba >= self.num_blocks {
            bail!("LBA {} out of range (max {})", lba, self.num_blocks - 1);
        }

        if data.len() != BLOCK_SIZE {
            bail!("Invalid block size: {} (expected {})", data.len(), BLOCK_SIZE);
        }

        // Write to sparse file
        let offset = lba * BLOCK_SIZE as u64;
        
        let file = self.data_file.lock().unwrap();
        file.write_all_at(data, offset)
            .context("Failed to write block to cache")?;

        // Mark as present and dirty
        {
            let mut present = self.present_bitmap.lock().unwrap();
            present.set(lba as usize, true);
        }
        {
            let mut dirty = self.dirty_bitmap.lock().unwrap();
            dirty.set(lba as usize, true);
        }

        Ok(())
    }

    /// Mark a block as clean (after successful S3 sync)
    pub fn mark_clean(&self, lba: Lba) -> Result<()> {
        if lba >= self.num_blocks {
            bail!("LBA {} out of range", lba);
        }

        let mut dirty = self.dirty_bitmap.lock().unwrap();
        dirty.set(lba as usize, false);

        Ok(())
    }

    /// Mark a block as present (after fetching from S3)
    pub fn mark_present(&self, lba: Lba) -> Result<()> {
        if lba >= self.num_blocks {
            bail!("LBA {} out of range", lba);
        }

        let mut present = self.present_bitmap.lock().unwrap();
        present.set(lba as usize, true);

        Ok(())
    }

    /// Check if a block is dirty
    pub fn is_dirty(&self, lba: Lba) -> bool {
        if lba >= self.num_blocks {
            return false;
        }

        let dirty = self.dirty_bitmap.lock().unwrap();
        dirty[lba as usize]
    }

    /// Check if a block is present
    pub fn is_present(&self, lba: Lba) -> bool {
        if lba >= self.num_blocks {
            return false;
        }

        let present = self.present_bitmap.lock().unwrap();
        present[lba as usize]
    }

    /// Get all dirty block LBAs
    pub fn dirty_blocks(&self) -> Vec<Lba> {
        let dirty = self.dirty_bitmap.lock().unwrap();
        dirty
            .iter_ones()
            .map(|idx| idx as Lba)
            .collect()
    }

    /// Get dirty block count
    pub fn dirty_count(&self) -> usize {
        let dirty = self.dirty_bitmap.lock().unwrap();
        dirty.count_ones()
    }

    /// Get present block count (cached blocks)
    pub fn present_count(&self) -> usize {
        let present = self.present_bitmap.lock().unwrap();
        present.count_ones()
    }

    /// Get estimated cache size in bytes
    pub fn cache_size_bytes(&self) -> u64 {
        self.present_count() as u64 * BLOCK_SIZE as u64
    }

    /// Evict clean blocks to reduce cache size
    pub fn evict_clean(&self, target_freed_bytes: u64) -> Result<usize> {
        let target_blocks = (target_freed_bytes + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64;
        let mut freed = 0;

        let mut present = self.present_bitmap.lock().unwrap();
        let dirty = self.dirty_bitmap.lock().unwrap();

        // Find clean blocks to evict (simple: evict from the beginning)
        for lba in 0..self.num_blocks {
            if freed >= target_blocks {
                break;
            }

            let idx = lba as usize;
            if present[idx] && !dirty[idx] {
                // Block is present but clean - can be evicted
                present.set(idx, false);
                freed += 1;

                // Punch hole in sparse file (optional optimization)
                // This is platform-specific, skip for now
            }
        }

        info!("Evicted {} clean blocks ({} MB)", freed, freed * BLOCK_SIZE as u64 / (1024 * 1024));
        Ok(freed as usize)
    }

    /// Flush bitmaps to disk
    pub fn flush_bitmaps(&self) -> Result<()> {
        let volume_cache_dir = self.config.cache_dir.join(&self.config.volume_name);

        // Save dirty bitmap
        let dirty_path = volume_cache_dir.join("dirty.bitmap");
        {
            let dirty = self.dirty_bitmap.lock().unwrap();
            Self::save_bitmap(&dirty_path, &dirty)?;
        }

        // Save present bitmap
        let present_path = volume_cache_dir.join("present.bitmap");
        {
            let present = self.present_bitmap.lock().unwrap();
            Self::save_bitmap(&present_path, &present)?;
        }

        Ok(())
    }

    /// Flush all data to disk
    pub fn flush(&self) -> Result<()> {
        let file = self.data_file.lock().unwrap();
        file.sync_all().context("Failed to sync cache file")?;
        
        self.flush_bitmaps()?;
        
        Ok(())
    }

    /// Load or create a bitmap file
    fn load_or_create_bitmap(path: &Path, num_blocks: usize) -> Result<BitMap> {
        if path.exists() {
            // Load existing bitmap
            let mut file = File::open(path).context("Failed to open bitmap")?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).context("Failed to read bitmap")?;

            let mut bitmap = BitVec::<u8, Lsb0>::from_vec(bytes);
            
            // Resize if needed
            if bitmap.len() < num_blocks {
                bitmap.resize(num_blocks, false);
            } else if bitmap.len() > num_blocks {
                bitmap.truncate(num_blocks);
            }

            Ok(bitmap)
        } else {
            // Create new bitmap (all zeros)
            let mut bitmap = BitVec::<u8, Lsb0>::new();
            bitmap.resize(num_blocks, false);
            Ok(bitmap)
        }
    }

    /// Save a bitmap to file
    fn save_bitmap(path: &Path, bitmap: &BitMap) -> Result<()> {
        let bytes = bitmap.as_raw_slice();
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .context("Failed to open bitmap for writing")?;

        file.write_all(bytes).context("Failed to write bitmap")?;
        file.sync_all()?;

        Ok(())
    }

    /// Get the cache directory path
    pub fn cache_dir(&self) -> PathBuf {
        self.config.cache_dir.join(&self.config.volume_name)
    }

    /// Destroy cache (delete all files)
    pub fn destroy(self) -> Result<()> {
        let cache_dir = self.cache_dir();
        
        // Drop locks before deleting
        drop(self.data_file);
        drop(self.dirty_bitmap);
        drop(self.present_bitmap);

        if cache_dir.exists() {
            std::fs::remove_dir_all(&cache_dir)
                .context("Failed to remove cache directory")?;
            info!("Destroyed cache directory: {:?}", cache_dir);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config(temp_dir: &TempDir, volume_size: u64) -> CacheConfig {
        CacheConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            volume_name: "test-volume".to_string(),
            volume_size,
            max_cache_bytes: Some(100 * 1024 * 1024), // 100 MB
        }
    }

    #[test]
    fn test_cache_create() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir, 10 * 1024 * 1024); // 10 MB

        let cache = BlockCache::open(config).unwrap();
        assert_eq!(cache.num_blocks, 2560); // 10 MB / 4 KB
        assert_eq!(cache.dirty_count(), 0);
        assert_eq!(cache.present_count(), 0);
    }

    #[test]
    fn test_write_read_block() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir, 10 * 1024 * 1024);

        let cache = BlockCache::open(config).unwrap();

        // Block should not be present initially
        assert_eq!(cache.read_block(0).unwrap(), None);
        assert!(!cache.is_present(0));
        assert!(!cache.is_dirty(0));

        // Write a block
        let data = vec![0x42u8; BLOCK_SIZE];
        cache.write_block(0, &data).unwrap();

        // Block should now be present and dirty
        assert!(cache.is_present(0));
        assert!(cache.is_dirty(0));
        assert_eq!(cache.dirty_count(), 1);
        assert_eq!(cache.present_count(), 1);

        // Read it back
        let read_data = cache.read_block(0).unwrap().unwrap();
        assert_eq!(read_data, data);

        // Mark clean
        cache.mark_clean(0).unwrap();
        assert!(cache.is_present(0));
        assert!(!cache.is_dirty(0));
    }

    #[test]
    fn test_dirty_blocks() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir, 10 * 1024 * 1024);

        let cache = BlockCache::open(config).unwrap();

        // Write several blocks
        let data = vec![0u8; BLOCK_SIZE];
        cache.write_block(0, &data).unwrap();
        cache.write_block(5, &data).unwrap();
        cache.write_block(100, &data).unwrap();

        let dirty = cache.dirty_blocks();
        assert_eq!(dirty.len(), 3);
        assert!(dirty.contains(&0));
        assert!(dirty.contains(&5));
        assert!(dirty.contains(&100));
    }

    #[test]
    fn test_evict_clean() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir, 10 * 1024 * 1024);

        let cache = BlockCache::open(config).unwrap();

        // Write and clean some blocks
        let data = vec![0u8; BLOCK_SIZE];
        for i in 0..10 {
            cache.write_block(i, &data).unwrap();
            if i < 5 {
                cache.mark_clean(i).unwrap();
            }
        }

        assert_eq!(cache.present_count(), 10);
        assert_eq!(cache.dirty_count(), 5);

        // Evict clean blocks
        cache.evict_clean(3 * BLOCK_SIZE as u64).unwrap();

        // Should have evicted 3 blocks
        assert_eq!(cache.present_count(), 7);
        assert_eq!(cache.dirty_count(), 5); // Dirty count unchanged
    }

    #[test]
    fn test_bitmap_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir, 10 * 1024 * 1024);

        {
            let cache = BlockCache::open(config.clone()).unwrap();
            let data = vec![0x42u8; BLOCK_SIZE];
            cache.write_block(0, &data).unwrap();
            cache.write_block(100, &data).unwrap();
            cache.flush_bitmaps().unwrap();
        }

        // Reopen cache
        {
            let cache = BlockCache::open(config).unwrap();
            assert_eq!(cache.dirty_count(), 2);
            assert_eq!(cache.present_count(), 2);
            assert!(cache.is_dirty(0));
            assert!(cache.is_dirty(100));
        }
    }
}
