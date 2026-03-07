//! S3 backup utilities (compress/upload, download/restore, delete).

use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::ServerSideEncryption;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

use crate::db;

#[derive(Debug, Clone)]
struct S3BackupConfig {
    bucket: String,
    prefix: String,
    endpoint: Option<String>,
    sse: Option<String>,
    kms_key_id: Option<String>,
}

impl S3BackupConfig {
    fn from_env() -> Result<Self> {
        Ok(Self {
            bucket: std::env::var("MINIONS_BACKUP_S3_BUCKET").unwrap_or_default(),
            prefix: std::env::var("MINIONS_BACKUP_S3_PREFIX")
                .unwrap_or_else(|_| "minions/v1".to_string()),
            endpoint: std::env::var("MINIONS_BACKUP_S3_ENDPOINT").ok(),
            sse: std::env::var("MINIONS_BACKUP_S3_SSE").ok(),
            kms_key_id: std::env::var("MINIONS_BACKUP_S3_KMS_KEY_ID").ok(),
        })
    }

    fn object_key(
        &self,
        host_id: Option<&str>,
        vm_name: &str,
        backup_name: &str,
        backup_id: &str,
    ) -> String {
        let host = host_id.unwrap_or("local");
        let leaf = format!("{backup_name}-{backup_id}.ext4.zst");
        let prefix = self.prefix.trim_matches('/');
        if prefix.is_empty() {
            format!("{host}/{vm_name}/{leaf}")
        } else {
            format!("{prefix}/{host}/{vm_name}/{leaf}")
        }
    }
}

#[derive(Debug, Clone)]
pub struct UploadedBackup {
    pub bucket: String,
    pub object_key: String,
    pub checksum_sha256: String,
    pub size_bytes_compressed: u64,
    pub size_bytes_uncompressed: u64,
}

async fn s3_client(cfg: &S3BackupConfig) -> Result<aws_sdk_s3::Client> {
    let region_override = std::env::var("MINIONS_BACKUP_S3_REGION").ok();
    let region_provider =
        RegionProviderChain::first_try(region_override.map(Region::new)).or_default_provider();

    let shared = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;

    let mut builder = aws_sdk_s3::config::Builder::from(&shared);

    if let Some(endpoint) = cfg.endpoint.as_deref() {
        builder = builder.endpoint_url(endpoint).force_path_style(true);
    }

    Ok(aws_sdk_s3::Client::from_conf(builder.build()))
}

/// Compress + upload a rootfs image to S3.
pub async fn upload_rootfs_to_s3(
    source_rootfs: &str,
    vm_name: &str,
    backup_name: &str,
    backup_id: &str,
    host_id: Option<&str>,
) -> Result<UploadedBackup> {
    let cfg = S3BackupConfig::from_env()?;
    if cfg.bucket.trim().is_empty() {
        anyhow::bail!("MINIONS_BACKUP_S3_BUCKET is required");
    }
    let client = s3_client(&cfg).await?;

    let source_path = PathBuf::from(source_rootfs);
    if !source_path.exists() {
        anyhow::bail!("rootfs not found at '{}'", source_path.display());
    }

    let compressed_path = PathBuf::from(format!("/tmp/minions-backup-{backup_id}.ext4.zst"));

    let (checksum_sha256, size_bytes_uncompressed) = tokio::task::spawn_blocking({
        let source_path = source_path.clone();
        let compressed_path = compressed_path.clone();
        move || compress_and_hash(&source_path, &compressed_path)
    })
    .await
    .context("backup compression task panicked")?
    .context("compress rootfs for backup")?;

    let size_bytes_compressed = std::fs::metadata(&compressed_path)
        .map(|m| m.len())
        .context("read compressed backup size")?;

    let object_key = cfg.object_key(host_id, vm_name, backup_name, backup_id);
    let body = ByteStream::from_path(&compressed_path)
        .await
        .context("open compressed backup stream")?;

    let mut req = client
        .put_object()
        .bucket(&cfg.bucket)
        .key(&object_key)
        .body(body);

    if let Some(sse) = cfg.sse.as_deref() {
        let sse_lc = sse.trim().to_ascii_lowercase();
        if sse_lc == "aes256" {
            req = req.server_side_encryption(ServerSideEncryption::Aes256);
        } else if sse_lc == "aws:kms" {
            req = req.server_side_encryption(ServerSideEncryption::AwsKms);
            if let Some(kms_key_id) = cfg.kms_key_id.as_deref() {
                req = req.ssekms_key_id(kms_key_id);
            }
        }
    }

    let upload_result = req
        .send()
        .await
        .with_context(|| format!("upload backup to s3://{}/{}", cfg.bucket, object_key));

    let _ = std::fs::remove_file(&compressed_path);

    upload_result?;

    Ok(UploadedBackup {
        bucket: cfg.bucket,
        object_key,
        checksum_sha256,
        size_bytes_compressed,
        size_bytes_uncompressed,
    })
}

/// Download + restore a backup object into a VM rootfs.
pub async fn restore_rootfs_from_s3(backup: &db::Backup, target_rootfs: &str) -> Result<()> {
    let cfg = S3BackupConfig::from_env()?;
    let client = s3_client(&cfg).await?;

    let compressed_path = PathBuf::from(format!("/tmp/minions-restore-{}.ext4.zst", backup.id));
    let staged_rootfs = PathBuf::from(format!(
        "{target_rootfs}.restore-{}.tmp",
        uuid::Uuid::new_v4()
    ));

    let download_result = async {
        let resp = client
            .get_object()
            .bucket(&backup.bucket)
            .key(&backup.object_key)
            .send()
            .await
            .with_context(|| {
                format!(
                    "download backup from s3://{}/{}",
                    backup.bucket, backup.object_key
                )
            })?;

        let mut body = resp.body.into_async_read();
        let mut out = tokio::fs::File::create(&compressed_path)
            .await
            .with_context(|| format!("create {}", compressed_path.display()))?;
        tokio::io::copy(&mut body, &mut out)
            .await
            .context("write downloaded backup")?;
        out.flush().await.context("flush downloaded backup")?;

        anyhow::Ok(())
    }
    .await;

    if let Err(e) = download_result {
        let _ = std::fs::remove_file(&compressed_path);
        return Err(e);
    }

    let decode_result = tokio::task::spawn_blocking({
        let compressed_path = compressed_path.clone();
        let staged_rootfs = staged_rootfs.clone();
        move || decompress_and_hash(&compressed_path, &staged_rootfs)
    })
    .await
    .context("backup decompression task panicked")?;

    let _ = std::fs::remove_file(&compressed_path);

    let restored_checksum = match decode_result {
        Ok(checksum) => checksum,
        Err(e) => {
            let _ = std::fs::remove_file(&staged_rootfs);
            return Err(e);
        }
    };

    if !constant_time_eq_hex(
        restored_checksum.as_bytes(),
        backup.checksum_sha256.as_bytes(),
    ) {
        let _ = std::fs::remove_file(&staged_rootfs);
        anyhow::bail!(
            "backup checksum mismatch (expected {}, got {})",
            backup.checksum_sha256,
            restored_checksum
        );
    }

    let replace_result = replace_rootfs_atomically(Path::new(target_rootfs), &staged_rootfs);
    if let Err(e) = replace_result {
        let _ = std::fs::remove_file(&staged_rootfs);
        return Err(e);
    }

    Ok(())
}

/// Delete a backup object from S3.
pub async fn delete_backup_object(backup: &db::Backup) -> Result<()> {
    let cfg = S3BackupConfig::from_env()?;
    let client = s3_client(&cfg).await?;

    client
        .delete_object()
        .bucket(&backup.bucket)
        .key(&backup.object_key)
        .send()
        .await
        .with_context(|| {
            format!(
                "delete backup object s3://{}/{}",
                backup.bucket, backup.object_key
            )
        })?;

    Ok(())
}

fn compress_and_hash(source_path: &Path, compressed_path: &Path) -> Result<(String, u64)> {
    let mut input = std::fs::File::open(source_path)
        .with_context(|| format!("open {}", source_path.display()))?;
    let compressed_file = std::fs::File::create(compressed_path)
        .with_context(|| format!("create {}", compressed_path.display()))?;

    let mut encoder = zstd::Encoder::new(compressed_file, 3).context("init zstd encoder")?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];

    loop {
        let n = input.read(&mut buf).context("read source rootfs")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        encoder
            .write_all(&buf[..n])
            .context("write compressed backup")?;
        total += n as u64;
    }

    let mut compressed_file = encoder.finish().context("finish zstd stream")?;
    compressed_file.flush().ok();

    Ok((hex::encode(hasher.finalize()), total))
}

fn decompress_and_hash(compressed_path: &Path, staged_rootfs: &Path) -> Result<String> {
    let compressed_file = std::fs::File::open(compressed_path)
        .with_context(|| format!("open {}", compressed_path.display()))?;
    let mut decoder = zstd::Decoder::new(compressed_file).context("init zstd decoder")?;

    let mut output = std::fs::File::create(staged_rootfs)
        .with_context(|| format!("create {}", staged_rootfs.display()))?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];

    loop {
        let n = decoder.read(&mut buf).context("read compressed backup")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        output
            .write_all(&buf[..n])
            .context("write restored rootfs")?;
    }

    output.sync_all().context("sync restored rootfs")?;

    Ok(hex::encode(hasher.finalize()))
}

fn replace_rootfs_atomically(target_rootfs: &Path, staged_rootfs: &Path) -> Result<()> {
    if !target_rootfs.exists() {
        anyhow::bail!("target rootfs not found at '{}'", target_rootfs.display());
    }
    if !staged_rootfs.exists() {
        anyhow::bail!(
            "staged restored rootfs not found at '{}'",
            staged_rootfs.display()
        );
    }

    let parent = target_rootfs
        .parent()
        .with_context(|| format!("resolve parent dir for {}", target_rootfs.display()))?;
    let old_rootfs = parent.join(format!("rootfs.ext4.pre-restore-{}", uuid::Uuid::new_v4()));

    std::fs::rename(target_rootfs, &old_rootfs)
        .with_context(|| format!("move current rootfs to {}", old_rootfs.display()))?;

    if let Err(e) = std::fs::rename(staged_rootfs, target_rootfs) {
        let _ = std::fs::rename(&old_rootfs, target_rootfs);
        return Err(anyhow::anyhow!(e).context("replace rootfs with restored backup"));
    }

    let _ = std::fs::remove_file(old_rootfs);
    Ok(())
}

fn constant_time_eq_hex(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a == b
}
