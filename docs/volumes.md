# Minions Volumes

S3-backed persistent storage for VMs.

## Overview

Volumes are persistent block devices stored in S3-compatible object storage (AWS S3, MinIO, Cloudflare R2, etc.). They can be attached to VMs for persistent data storage that survives VM destruction and can be moved between VMs.

## Features

- **S3-backed**: Data stored in S3 for durability and accessibility
- **Local caching**: Fast reads/writes with local SSD cache
- **Async sync**: Background sync to S3 (configurable interval)
- **NBD protocol**: Standard Linux block device interface
- **VM-portable**: Detach from one VM, attach to another
- **Size flexibility**: Create volumes from 1GB to multiple TBs

## Configuration

Set these environment variables before using volumes:

```bash
# Required
export MINIONS_S3_ENDPOINT=http://localhost:9000      # S3-compatible endpoint
export MINIONS_S3_BUCKET=minions-volumes              # Bucket name
export MINIONS_S3_ACCESS_KEY=minioadmin               # Access key
export MINIONS_S3_SECRET_KEY=minioadmin               # Secret key
export MINIONS_S3_REGION=us-east-1                    # Region

# Optional (with defaults)
export MINIONS_VOLUME_CACHE_DIR=/var/lib/minions/volume-cache  # Cache location
export MINIONS_VOLUME_CACHE_MAX_GB=50                 # Max cache size
export MINIONS_VOLUME_SYNC_INTERVAL=30                # Seconds between syncs
```

### MinIO Setup (for development)

```bash
# Start MinIO
docker run -d -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data --console-address ":9001"

# Create bucket
mc alias set local http://localhost:9000 minioadmin minioadmin
mc mb local/minions-volumes
```

## Commands

### Create a Volume

```bash
sudo minions volume create <name> --size <gb>
```

Example:
```bash
sudo minions volume create data --size 10
# Creates a 10GB volume named 'data'
```

### List Volumes

```bash
sudo minions volume list
```

Output:
```
┌──────────┬────────┬───────────┬──────┬──────────┐
│ NAME     │ SIZE   │ STATUS    │ VM   │ DEVICE   │
├──────────┼────────┼───────────┼──────┼──────────┤
│ data-vol │ 10 GB  │ available │ -    │ -        │
│ logs-vol │ 5 GB   │ attached  │ myvm │ /dev/nbd0│
└──────────┴────────┴───────────┴──────┴──────────┘
```

### Get Volume Status

```bash
sudo minions volume status <name>
```

Example:
```bash
sudo minions volume status data

# Output:
✓ Volume 'data'
  Size:   10 GB
  Status: available
  Bucket: minions-volumes
  S3 Prefix: volumes/data
```

### Attach Volume to VM

```bash
sudo minions volume attach <vm-name> <volume-name>
```

Example:
```bash
# Attach to stopped VM
sudo minions volume attach myvm data

# Start VM - volume automatically attached!
sudo minions start myvm

# Inside VM, the volume appears as /dev/vdb (or next available device)
```

**Note**: Volumes are **persistently attached**. Once attached, they automatically reconnect when the VM starts.

### Detach Volume from VM

```bash
sudo minions volume detach <vm-name> <volume-name>
```

Example:
```bash
sudo minions volume detach myvm data
```

### Destroy Volume

```bash
sudo minions volume destroy <name>
```

Example:
```bash
sudo minions volume destroy data
# Deletes volume from S3 and database
```

**Warning**: This is permanent! All data will be lost.

## Volume Status

A volume can be in one of these states:

- **`available`** - Ready to attach
- **`attached`** - Currently attached to a VM
- **`syncing`** - Background sync in progress (future)
- **`error`** - Error state requiring attention (future)

## Auto-Attach on Start

**Volumes are persistent!** Once attached to a VM, they automatically reconnect on every start.

### How It Works

```bash
# 1. Attach volume to stopped VM
sudo minions volume attach myvm data

# 2. Start VM - volume automatically attached
sudo minions start myvm
# Output: Attaching volumes for VM 'myvm'...
#         Found 1 volume(s) to attach
#         ✓ data → /dev/nbd0

# 3. Stop VM - volume disconnected but attachment preserved
sudo minions stop myvm
# Output: Disconnecting 1 volume(s) from VM 'myvm'

# 4. Restart - volume automatically reattached
sudo minions start myvm
# Output: ✓ data → /dev/nbd0
```

### Persistent vs Temporary

| Action | NBD Connection | Database | Next Start |
|--------|----------------|----------|------------|
| `attach` | ✓ Connected | ✓ Recorded | Auto-attaches |
| `stop` | ✗ Disconnected | ✓ Preserved | Auto-attaches |
| `detach` | ✗ Disconnected | ✗ Cleared | Not attached |

**To remove attachment permanently**:
```bash
sudo minions volume detach myvm data
```

## Using Volumes in VMs

Attached volumes appear as block devices inside the VM:

```bash
# Attach volume and start VM
sudo minions volume attach myvm data
sudo minions start myvm

# Inside VM, check available disks
ssh root@10.0.0.2 lsblk
# NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
# vda      252:0    0   10G  0 disk
# └─vda1   252:1    0   10G  0 part /
# vdb      252:16   0   10G  0 disk         # ← Your volume

# Format the volume (first time only)
sudo mkfs.ext4 /dev/vdb

# Mount it
sudo mkdir -p /data
sudo mount /dev/vdb /data

# Make mount permanent (survives reboots)
echo '/dev/vdb /data ext4 defaults 0 0' | sudo tee -a /etc/fstab
```

**Tip**: Use filesystem labels for stability across restarts:
```bash
# Create filesystem with label
sudo mkfs.ext4 -L mydata /dev/vdb

# Mount by label (device path may change between starts)
echo 'LABEL=mydata /data ext4 defaults 0 0' | sudo tee -a /etc/fstab
```

## Remote Mode

Use volumes with a remote minions daemon:

```bash
export MINIONS_API_KEY=your-api-key

minions --host http://my-server:3000 volume list
minions --host http://my-server:3000 volume create data --size 10
minions --host http://my-server:3000 volume attach myvm data
```

## JSON Output

Get machine-readable output:

```bash
minions --json volume list
minions --json volume status data
```

Example output:
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "data-vol",
    "size_bytes": 10737418240,
    "status": "available",
    "vm_name": null,
    "nbd_device": null,
    "s3_bucket": "minions-volumes",
    "s3_prefix": "volumes/data-vol",
    "host_id": null,
    "created_at": "2024-03-06T12:00:00Z"
  }
]
```

## API Usage

### Create Volume

```bash
curl -X POST http://localhost:3000/api/volumes \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "data", "size_gb": 10}'
```

### List Volumes

```bash
curl http://localhost:3000/api/volumes \
  -H "Authorization: Bearer $TOKEN"
```

### Attach Volume

```bash
curl -X POST http://localhost:3000/api/volumes/data/attach \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"vm_name": "myvm"}'
```

### Detach Volume

```bash
curl -X POST http://localhost:3000/api/volumes/data/detach \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"vm_name": "myvm"}'
```

### Destroy Volume

```bash
curl -X DELETE http://localhost:3000/api/volumes/data \
  -H "Authorization: Bearer $TOKEN"
```

## Best Practices

1. **Use filesystem labels**: Device paths may change; use `LABEL=` in `/etc/fstab`
2. **Attach before start**: Attach volumes to stopped VMs for auto-connection on start
3. **Regular backups**: Even though data is in S3, consider volume snapshots
4. **Monitor sync**: Check sync intervals match your durability requirements
5. **Cache sizing**: Size cache appropriately for your workload (hot data set)
6. **Detach before destroy**: Always detach volumes from VMs before destroying them
7. **Name consistently**: Use descriptive names like `<vm>-data` or `<app>-logs`

## Current Limitations

Known constraints:

1. **No hot-add/remove**: Cannot attach/detach while VM is running (must stop first)
2. **Device path variability**: NBD device paths (`/dev/nbdX`) may change between restarts
   - **Workaround**: Use filesystem labels (`LABEL=`) in `/etc/fstab`
3. **Manual eviction only**: No automatic cache eviction under pressure
4. **Async durability**: Writes buffered locally (30s sync interval by default)

## Troubleshooting

### "S3 configuration not set"

Set the required environment variables:
```bash
export MINIONS_S3_ENDPOINT=...
export MINIONS_S3_BUCKET=...
export MINIONS_S3_ACCESS_KEY=...
export MINIONS_S3_SECRET_KEY=...
```

### "Volume already exists"

Choose a different name or destroy the existing volume first.

### "Volume not available"

The volume is already attached to another VM. Detach it first:
```bash
sudo minions volume detach <other-vm> <volume>
```

### "Volume not found"

Check the volume name:
```bash
sudo minions volume list
```

## Architecture

```
┌─────────────────────────────┐
│      Cloud Hypervisor VM    │
│     /dev/vdb block device   │
└──────────┬──────────────────┘
           │
      NBD kernel module
           │
      Unix socket
           │
┌──────────┴──────────────────┐
│   minions-volume engine     │
│  ┌──────────────────────┐   │
│  │  NBD Server          │   │
│  │  Block Cache         │   │
│  │  Background S3 Sync  │   │
│  └──────────────────────┘   │
└─────────────┬───────────────┘
              │
         ┌────┴────┐
         │   S3    │
         └─────────┘
```

## Performance

- **Cache hit (read)**: ~10μs (local SSD)
- **Cache miss (read)**: ~50-200ms (S3 fetch)
- **Write**: ~10μs (local cache, async sync)
- **Flush**: ~100-500ms (depends on dirty blocks)

Tune `MINIONS_VOLUME_SYNC_INTERVAL` based on your durability vs. performance requirements.

## Future Features (Roadmap)

- Volume snapshots (metadata-only, instant)
- Volume cloning
- Volume resize
- Multiple volumes per VM
- Hot-add/remove support
- Sync mode (writes wait for S3 ACK)
- Volume encryption
- Volume migration between hosts
- Read-only volume sharing

## See Also

- [Architecture Overview](../crates/minions-volume/README.md)
- [Issue #45](https://github.com/your-repo/minions/issues/45) - Full specification
- [API Documentation](api.md)
