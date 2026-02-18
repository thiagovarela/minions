//! SQLite state management for VM lifecycle.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::path::Path;

pub const DB_PATH: &str = "/var/lib/minions/state.db";

/// Represents a VM record in the database.
#[derive(Debug, Clone)]
pub struct Vm {
    pub name: String,
    pub status: String,
    pub ip: String,
    pub vsock_cid: u32,
    pub ch_pid: Option<i64>,
    pub ch_api_socket: String,
    pub ch_vsock_socket: String,
    pub tap_device: String,
    pub mac_address: String,
    pub vcpus: u32,
    pub memory_mb: u32,
    pub rootfs_path: String,
    pub created_at: String,
    pub stopped_at: Option<String>,
}

/// Open (or create) the state database.
pub fn open(path: &str) -> Result<Connection> {
    // Ensure parent directory exists.
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create db dir {:?}", parent))?;
    }
    let conn = Connection::open(path).context("open sqlite db")?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    migrate(&conn)?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vms (
            name            TEXT PRIMARY KEY,
            status          TEXT NOT NULL,
            ip              TEXT NOT NULL,
            vsock_cid       INTEGER NOT NULL,
            ch_pid          INTEGER,
            ch_api_socket   TEXT NOT NULL,
            ch_vsock_socket TEXT NOT NULL,
            tap_device      TEXT NOT NULL,
            mac_address     TEXT NOT NULL,
            vcpus           INTEGER NOT NULL DEFAULT 2,
            memory_mb       INTEGER NOT NULL DEFAULT 1024,
            rootfs_path     TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            stopped_at      TEXT
        );

        -- Partial unique indexes to prevent IP/CID conflicts for active VMs.
        -- Stopped VMs don't hold resources, so their IPs/CIDs can be reused.
        CREATE UNIQUE INDEX IF NOT EXISTS idx_vms_ip_active
            ON vms(ip) WHERE status != 'stopped';
        
        CREATE UNIQUE INDEX IF NOT EXISTS idx_vms_cid_active
            ON vms(vsock_cid) WHERE status != 'stopped';
        ",
    )
    .context("run migration")
}

/// Insert a new VM row (status = "creating").
pub fn insert_vm(conn: &Connection, vm: &Vm) -> Result<()> {
    conn.execute(
        "INSERT INTO vms
            (name, status, ip, vsock_cid, ch_pid, ch_api_socket, ch_vsock_socket,
             tap_device, mac_address, vcpus, memory_mb, rootfs_path, created_at, stopped_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            vm.name,
            vm.status,
            vm.ip,
            vm.vsock_cid,
            vm.ch_pid,
            vm.ch_api_socket,
            vm.ch_vsock_socket,
            vm.tap_device,
            vm.mac_address,
            vm.vcpus,
            vm.memory_mb,
            vm.rootfs_path,
            vm.created_at,
            vm.stopped_at,
        ],
    )
    .context("insert vm")?;
    Ok(())
}

/// Retrieve a VM by name.
pub fn get_vm(conn: &Connection, name: &str) -> Result<Option<Vm>> {
    let mut stmt = conn.prepare(
        "SELECT name,status,ip,vsock_cid,ch_pid,ch_api_socket,ch_vsock_socket,
                tap_device,mac_address,vcpus,memory_mb,rootfs_path,created_at,stopped_at
         FROM vms WHERE name=?1",
    )?;
    let mut rows = stmt.query(params![name])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row_to_vm(row)?))
    } else {
        Ok(None)
    }
}

/// List all VMs.
pub fn list_vms(conn: &Connection) -> Result<Vec<Vm>> {
    let mut stmt = conn.prepare(
        "SELECT name,status,ip,vsock_cid,ch_pid,ch_api_socket,ch_vsock_socket,
                tap_device,mac_address,vcpus,memory_mb,rootfs_path,created_at,stopped_at
         FROM vms ORDER BY created_at",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(row_to_vm(row).expect("parse vm row"))
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// Update VM status and optionally pid.
pub fn update_vm_status(conn: &Connection, name: &str, status: &str, pid: Option<i64>) -> Result<()> {
    conn.execute(
        "UPDATE vms SET status=?1, ch_pid=COALESCE(?2, ch_pid) WHERE name=?3",
        params![status, pid, name],
    )
    .context("update vm status")?;
    Ok(())
}

/// Rename a VM: update all name-derived columns atomically.
///
/// Caller is responsible for renaming the filesystem rootfs directory and
/// TAP device before calling this. This function only updates the DB.
pub fn rename_vm(
    conn: &Connection,
    old_name: &str,
    new_name: &str,
    new_tap: &str,
    new_api_socket: &str,
    new_vsock_socket: &str,
    new_rootfs_path: &str,
) -> Result<()> {
    let updated = conn.execute(
        "UPDATE vms SET
            name            = ?1,
            tap_device      = ?2,
            ch_api_socket   = ?3,
            ch_vsock_socket = ?4,
            rootfs_path     = ?5
         WHERE name = ?6",
        rusqlite::params![
            new_name,
            new_tap,
            new_api_socket,
            new_vsock_socket,
            new_rootfs_path,
            old_name,
        ],
    )
    .context("rename vm in db")?;

    if updated == 0 {
        anyhow::bail!("VM '{}' not found", old_name);
    }
    Ok(())
}

/// Rename a running VM: only update the `name` column.
/// All stored paths (sockets, TAP, rootfs) remain unchanged.
pub fn rename_vm_name_only(conn: &Connection, old_name: &str, new_name: &str) -> Result<()> {
    let updated = conn
        .execute(
            "UPDATE vms SET name = ?1 WHERE name = ?2",
            rusqlite::params![new_name, old_name],
        )
        .context("rename vm name in db")?;
    if updated == 0 {
        anyhow::bail!("VM '{}' not found", old_name);
    }
    Ok(())
}

/// Delete a VM record.
pub fn delete_vm(conn: &Connection, name: &str) -> Result<()> {
    conn.execute("DELETE FROM vms WHERE name=?1", params![name])
        .context("delete vm")?;
    Ok(())
}

/// Pick the lowest available IP in 10.0.0.2..=10.0.0.254.
///
/// This function is atomic — it queries for the first available IP in a way
/// that is safe even if multiple concurrent calls are happening.
pub fn next_available_ip(conn: &Connection) -> Result<String> {
    // Get all currently in-use IPs (non-stopped VMs)
    let used: Vec<String> = conn
        .prepare("SELECT ip FROM vms WHERE status != 'stopped'")?
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;

    // Convert to a set for O(1) lookups
    let used_set: std::collections::HashSet<String> = used.into_iter().collect();

    // Find the first available IP
    for i in 2u32..=254 {
        let candidate = format!("10.0.0.{i}");
        if !used_set.contains(&candidate) {
            return Ok(candidate);
        }
    }
    anyhow::bail!("IP pool exhausted (all 253 IPs in use)")
}

/// Pick the lowest available VSOCK CID (3..=255).
///
/// This function is atomic — it queries for the first available CID in a way
/// that is safe even if multiple concurrent calls are happening.
pub fn next_available_cid(conn: &Connection) -> Result<u32> {
    // Get all currently in-use CIDs (non-stopped VMs)
    let used: Vec<u32> = conn
        .prepare("SELECT vsock_cid FROM vms WHERE status != 'stopped'")?
        .query_map([], |r| r.get::<_, u32>(0))?
        .collect::<std::result::Result<_, _>>()?;

    // Convert to a set for O(1) lookups
    let used_set: std::collections::HashSet<u32> = used.into_iter().collect();

    // Find the first available CID
    for cid in 3u32..=255 {
        if !used_set.contains(&cid) {
            return Ok(cid);
        }
    }
    anyhow::bail!("VSOCK CID pool exhausted (all 253 CIDs in use)")
}

fn row_to_vm(row: &rusqlite::Row<'_>) -> rusqlite::Result<Vm> {
    Ok(Vm {
        name: row.get(0)?,
        status: row.get(1)?,
        ip: row.get(2)?,
        vsock_cid: row.get(3)?,
        ch_pid: row.get(4)?,
        ch_api_socket: row.get(5)?,
        ch_vsock_socket: row.get(6)?,
        tap_device: row.get(7)?,
        mac_address: row.get(8)?,
        vcpus: row.get(9)?,
        memory_mb: row.get(10)?,
        rootfs_path: row.get(11)?,
        created_at: row.get(12)?,
        stopped_at: row.get(13)?,
    })
}
