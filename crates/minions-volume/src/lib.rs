//! Minions Volume - S3-backed block storage via NBD
//!
//! Provides S3-backed volumes that can be attached to VMs via Network Block Device (NBD).
//! Features local caching for performance with background sync to S3 for durability.

pub mod cache;
pub mod nbd;
pub mod s3;
pub mod sync;
pub mod volume;

pub use volume::{VolumeConfig, VolumeHandle};

/// Volume size in bytes
pub type VolumeSize = u64;

/// Logical Block Address (512-byte sectors)
pub type Lba = u64;

/// Block size - 4KB blocks
pub const BLOCK_SIZE: usize = 4096;

/// Segment size - 4MB segments (1024 blocks)
pub const SEGMENT_SIZE: usize = 4 * 1024 * 1024;
pub const BLOCKS_PER_SEGMENT: usize = SEGMENT_SIZE / BLOCK_SIZE;

/// Segment ID
pub type SegmentId = u64;

/// Convert LBA to segment ID and block offset within segment
pub fn lba_to_segment(lba: Lba) -> (SegmentId, usize) {
    let block_idx = lba;
    let segment_id = block_idx / BLOCKS_PER_SEGMENT as u64;
    let block_offset = (block_idx % BLOCKS_PER_SEGMENT as u64) as usize;
    (segment_id, block_offset)
}

/// Convert segment ID and block offset to LBA
pub fn segment_to_lba(segment_id: SegmentId, block_offset: usize) -> Lba {
    segment_id * BLOCKS_PER_SEGMENT as u64 + block_offset as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lba_segment_conversion() {
        // First block of first segment
        assert_eq!(lba_to_segment(0), (0, 0));
        
        // Last block of first segment
        assert_eq!(lba_to_segment(1023), (0, 1023));
        
        // First block of second segment
        assert_eq!(lba_to_segment(1024), (1, 0));
        
        // Round trip
        let lba = 5000;
        let (seg, offset) = lba_to_segment(lba);
        assert_eq!(segment_to_lba(seg, offset), lba);
    }
}
