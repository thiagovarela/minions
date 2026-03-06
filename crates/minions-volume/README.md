# minions-volume

S3-backed block storage for Minions VMs via NBD (Network Block Device).

## Overview

`minions-volume` provides persistent, S3-backed volumes that can be attached to VMs. It implements a custom NBD server in Rust that presents S3 objects as block devices with local caching for performance.

## Features

- **S3-backed storage**: Volume data stored in S3-compatible object storage (AWS S3, MinIO, R2, etc.)
- **Local caching**: Sparse file cache for performance with configurable size limits
- **Async background sync**: Dirty blocks synced to S3 periodically (configurable interval)
- **NBD protocol**: Standard Linux NBD protocol for VM integration
- **Shared storage**: Volumes can be moved between hosts (only one active at a time)
- **Efficient snapshots**: Metadata-only snapshots (future feature)

## Architecture

```
┌─────────────────────────────────┐
│       Cloud Hypervisor VM       │
│      --disk path=/dev/nbd0      │
└────────────┬────────────────────┘
             │
        /dev/nbd0 (NBD kernel module)
             │
        Unix socket
             │
┌────────────┴────────────────────┐
│    minions-volume engine        │
│  ┌──────────────────────────┐   │
│  │  NBD Server (async)      │   │
│  ├──────────────────────────┤   │
│  │  Block Cache (4KB blocks)│   │
│  │  + dirty/present bitmaps │   │
│  ├──────────────────────────┤   │
│  │  Background S3 Sync      │   │
│  ├──────────────────────────┤   │
│  │  S3 Backend              │   │
│  └──────────────────────────┘   │
└─────────────┬───────────────────┘
              │
         ┌────┴────┐
         │   S3    │
         └─────────┘
```

## Components

### NBD Server (`nbd.rs`)

Implements the NBD newstyle protocol:
- Handshake with client (option negotiation)
- Command handling: READ, WRITE, FLUSH, TRIM, DISC
- Async Unix socket server
- Supports FUA (Force Unit Access) and read-only mode

### S3 Backend (`s3.rs`)

Manages volume storage in S3:
- Volume metadata stored as `volumes/{name}/meta.json`
- Data stored as 4MB segments: `volumes/{name}/segments/{id}.bin`
- Supports any S3-compatible endpoint (MinIO, R2, etc.)
- CRUD operations for volumes and segments

### Block Cache (`cache.rs`)

Local cache for performance:
- Sparse file storage (only dirty/present blocks consume disk)
- BitVec-based dirty/present bitmaps for efficient tracking
- Configurable cache size with LRU eviction
- Persistent bitmaps across restarts

### Sync Engine (`sync.rs`)

Background synchronization to S3:
- Periodic sync (default: 30 seconds)
- Groups dirty blocks by segment for efficient uploads
- Forced sync on flush or close
- Read-Modify-Write for partial segment updates
- Statistics tracking

### Volume Manager (`volume.rs`)

High-level orchestration:
- Volume lifecycle: create, open, close, destroy
- Coordinates NBD server, cache, S3, and sync
- Implements NBD command handler
- Automatic S3 prefetch on cache miss

## Usage

### Configuration

Environment variables:
```bash
# S3 configuration (required)
export MINIONS_S3_ENDPOINT=http://localhost:9000  # or https://s3.amazonaws.com
export MINIONS_S3_BUCKET=minions-volumes
export MINIONS_S3_ACCESS_KEY=minioadmin
export MINIONS_S3_SECRET_KEY=minioadmin
export MINIONS_S3_REGION=us-east-1

# Cache configuration (optional)
export MINIONS_VOLUME_CACHE_DIR=/var/lib/minions/volume-cache
export MINIONS_VOLUME_CACHE_MAX_GB=50

# Sync configuration (optional)
export MINIONS_VOLUME_SYNC_INTERVAL=30  # seconds
```

### API Example

```rust
use minions_volume::{VolumeConfig, VolumeHandle};
use minions_volume::s3::S3Config;

#[tokio::main]
async fn main() -> Result<()> {
    // Configure S3
    let s3_config = S3Config::from_env()?;

    // Create a new 10GB volume
    let config = VolumeConfig::new(
        "data-vol".to_string(),
        10 * 1024 * 1024 * 1024,
        s3_config.clone()
    );
    VolumeHandle::create(config.clone()).await?;

    // Open the volume
    let volume = VolumeHandle::open(config).await?;
    println!("NBD socket: {:?}", volume.socket_path());

    // Connect nbd-client
    // $ nbd-client -unix /var/lib/minions/nbd/data-vol.sock /dev/nbd0

    // Flush and close
    volume.flush().await?;
    volume.close().await?;

    Ok(())
}
```

## S3 Object Layout

```
s3://bucket/volumes/{vol-name}/
  ├── meta.json                      # Volume metadata
  └── segments/
      ├── 0.bin                      # Segment 0 (4MB)
      ├── 1.bin                      # Segment 1 (4MB)
      └── ...
```

### Metadata Format

```json
{
  "name": "data-vol",
  "size_bytes": 10737418240,
  "block_size": 4096,
  "segment_size": 4194304,
  "created_at": "2024-03-06T12:00:00Z"
}
```

## Local Cache Layout

```
/var/lib/minions/volume-cache/{vol-name}/
  ├── data.img          # Sparse file (same size as volume)
  ├── dirty.bitmap      # Tracks dirty blocks (need S3 sync)
  └── present.bitmap    # Tracks cached blocks
```

## Performance Characteristics

- **Cache hit (read)**: ~10μs (local SSD)
- **Cache miss (read)**: ~50-200ms (S3 fetch + cache populate)
- **Write**: ~10μs (local cache, async S3 sync)
- **Flush**: ~100-500ms (depends on dirty block count)

## Durability

**Important**: This is an **async durability** system:
- Writes are ACKed immediately after local cache write
- S3 sync happens in background (default: every 30 seconds)
- Data written < 30s ago may be lost on host crash

For critical workloads:
- Use smaller sync intervals
- Trigger manual flushes after important writes
- Consider implementing sync mode (every write waits for S3 ACK)

## Testing

```bash
cargo test
```

Integration tests require a MinIO instance:
```bash
docker run -d -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data --console-address ":9001"
```

## Next Steps (Phase 2)

- [ ] Database integration for volume tracking
- [ ] CLI commands (`minions volume create/attach/detach/destroy`)
- [ ] API endpoints for volume management
- [ ] VM integration (attach/detach volumes to running VMs)
- [ ] Hot-add/remove disk support
- [ ] Volume snapshots
- [ ] Multi-host volume locking

## License

Same as parent Minions project.
