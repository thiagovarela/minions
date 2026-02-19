//! SQLite state management for VM lifecycle.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, params};
use std::path::Path;
use uuid::Uuid;

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
    /// Port the VM's web server listens on (default 80).
    pub proxy_port: u16,
    /// Whether the VM is publicly accessible without auth (default false).
    pub proxy_public: bool,
    /// SSH gateway user who owns this VM.
    /// NULL for VMs created directly via the HTTP API (admin/system VMs).
    pub owner_id: Option<String>,
}

/// Open (or create) the state database.
pub fn open(path: &str) -> Result<Connection> {
    // Ensure parent directory exists.
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create db dir {:?}", parent))?;
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
            stopped_at      TEXT,
            proxy_port      INTEGER NOT NULL DEFAULT 80,
            proxy_public    INTEGER NOT NULL DEFAULT 0,
            owner_id        TEXT
        );

        -- Partial unique indexes to prevent IP/CID conflicts for active VMs.
        -- Stopped VMs don't hold resources, so their IPs/CIDs can be reused.
        CREATE UNIQUE INDEX IF NOT EXISTS idx_vms_ip_active
            ON vms(ip) WHERE status != 'stopped';

        CREATE UNIQUE INDEX IF NOT EXISTS idx_vms_cid_active
            ON vms(vsock_cid) WHERE status != 'stopped';

        -- Custom domains table (for user-provided domains).
        CREATE TABLE IF NOT EXISTS custom_domains (
            id          TEXT PRIMARY KEY,
            vm_name     TEXT NOT NULL,
            domain      TEXT UNIQUE NOT NULL,
            verified    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL
        );

        -- Snapshots table: one row per snapshot.
        -- Snapshot files live at /var/lib/minions/snapshots/{vm_name}/{name}/rootfs.ext4
        CREATE TABLE IF NOT EXISTS snapshots (
            id          TEXT PRIMARY KEY,
            vm_name     TEXT NOT NULL,
            name        TEXT NOT NULL,
            size_bytes  INTEGER,
            created_at  TEXT NOT NULL,
            UNIQUE(vm_name, name)
        );

        -- Resource plans: defines limits per user tier.
        CREATE TABLE IF NOT EXISTS plans (
            id              TEXT PRIMARY KEY,
            name            TEXT UNIQUE NOT NULL,
            max_vms         INTEGER NOT NULL DEFAULT 2,
            max_vcpus       INTEGER NOT NULL DEFAULT 4,
            max_memory_mb   INTEGER NOT NULL DEFAULT 2048,
            max_disk_gb     INTEGER NOT NULL DEFAULT 20,
            max_snapshots   INTEGER NOT NULL DEFAULT 5,
            price_cents     INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL
        );

        -- User subscriptions: one row per user, links them to a plan.
        CREATE TABLE IF NOT EXISTS subscriptions (
            id                 TEXT PRIMARY KEY,
            user_id            TEXT NOT NULL,
            plan_id            TEXT NOT NULL REFERENCES plans(id),
            status             TEXT NOT NULL DEFAULT 'active',
            created_at         TEXT NOT NULL,
            UNIQUE(user_id)
        );
        ",
    )
    .context("run migration")?;

    // Seed built-in plans (idempotent — INSERT OR IGNORE).
    conn.execute_batch(
        "INSERT OR IGNORE INTO plans
            (id, name, max_vms, max_vcpus, max_memory_mb, max_disk_gb, max_snapshots, price_cents, created_at)
         VALUES ('free', 'Free', 2, 4, 2048, 20, 5, 0, '2025-01-01T00:00:00Z');

         INSERT OR IGNORE INTO plans
            (id, name, max_vms, max_vcpus, max_memory_mb, max_disk_gb, max_snapshots, price_cents, created_at)
         VALUES ('pro', 'Pro', 10, 32, 32768, 200, 20, 1200, '2025-01-01T00:00:00Z');
        ",
    )
    .context("seed plans")?;

    // Idempotent column additions for existing databases (errors are ignored
    // because SQLite errors on duplicate ADD COLUMN).
    let _ =
        conn.execute_batch("ALTER TABLE vms ADD COLUMN proxy_port   INTEGER NOT NULL DEFAULT 80;");
    let _ =
        conn.execute_batch("ALTER TABLE vms ADD COLUMN proxy_public  INTEGER NOT NULL DEFAULT 0;");
    let _ = conn.execute_batch("ALTER TABLE vms ADD COLUMN owner_id      TEXT;");
    // Index on owner_id — must come after the column exists (idempotent).
    let _ = conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_vms_owner ON vms(owner_id) WHERE owner_id IS NOT NULL;",
    );

    Ok(())
}

// ── Column list used in every SELECT ─────────────────────────────────────────
// Keeping it in one place makes column-index changes hard to miss.
// Indices: 0=name 1=status 2=ip 3=vsock_cid 4=ch_pid 5=ch_api_socket
//          6=ch_vsock_socket 7=tap_device 8=mac_address 9=vcpus
//          10=memory_mb 11=rootfs_path 12=created_at 13=stopped_at
//          14=proxy_port 15=proxy_public 16=owner_id
const VM_COLUMNS: &str = "name,status,ip,vsock_cid,ch_pid,ch_api_socket,ch_vsock_socket,\
     tap_device,mac_address,vcpus,memory_mb,rootfs_path,created_at,stopped_at,\
     proxy_port,proxy_public,owner_id";

/// Insert a new VM row (status = "creating").
pub fn insert_vm(conn: &Connection, vm: &Vm) -> Result<()> {
    conn.execute(
        "INSERT INTO vms
            (name, status, ip, vsock_cid, ch_pid, ch_api_socket, ch_vsock_socket,
             tap_device, mac_address, vcpus, memory_mb, rootfs_path, created_at, stopped_at,
             proxy_port, proxy_public, owner_id)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
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
            vm.proxy_port as i64,
            if vm.proxy_public { 1i64 } else { 0i64 },
            vm.owner_id,
        ],
    )
    .context("insert vm")?;
    Ok(())
}

/// Retrieve a VM by name (admin — no ownership check).
pub fn get_vm(conn: &Connection, name: &str) -> Result<Option<Vm>> {
    let sql = format!("SELECT {VM_COLUMNS} FROM vms WHERE name=?1");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params![name])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row_to_vm(row)?))
    } else {
        Ok(None)
    }
}

/// Retrieve a VM by name **and** verify it belongs to `owner_id`.
#[allow(dead_code)]
/// Returns `Ok(None)` if not found, `Err` if the VM exists but is owned by
/// someone else (caller should surface this as a 403).
pub fn get_vm_owned(conn: &Connection, name: &str, owner_id: &str) -> Result<Option<Vm>> {
    let sql = format!("SELECT {VM_COLUMNS} FROM vms WHERE name=?1");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params![name])?;
    match rows.next()? {
        None => Ok(None),
        Some(row) => {
            let vm = row_to_vm(row)?;
            match &vm.owner_id {
                Some(oid) if oid == owner_id => Ok(Some(vm)),
                Some(_) => anyhow::bail!("VM '{name}' belongs to another user"),
                None => anyhow::bail!("VM '{name}' belongs to another user"),
            }
        }
    }
}

/// List all VMs (admin — no ownership filter).
pub fn list_vms(conn: &Connection) -> Result<Vec<Vm>> {
    let sql = format!("SELECT {VM_COLUMNS} FROM vms ORDER BY created_at");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |row| Ok(row_to_vm(row).expect("parse vm row")))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// List only the VMs owned by a specific SSH gateway user.
pub fn list_vms_by_owner(conn: &Connection, owner_id: &str) -> Result<Vec<Vm>> {
    let sql = format!("SELECT {VM_COLUMNS} FROM vms WHERE owner_id=?1 ORDER BY created_at");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![owner_id], |row| {
        Ok(row_to_vm(row).expect("parse vm row"))
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// Update VM status and optionally pid.
pub fn update_vm_status(
    conn: &Connection,
    name: &str,
    status: &str,
    pid: Option<i64>,
) -> Result<()> {
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
    let updated = conn
        .execute(
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
pub fn next_available_ip(conn: &Connection) -> Result<String> {
    let used: Vec<String> = conn
        .prepare("SELECT ip FROM vms WHERE status != 'stopped'")?
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;

    let used_set: std::collections::HashSet<String> = used.into_iter().collect();

    for i in 2u32..=254 {
        let candidate = format!("10.0.0.{i}");
        if !used_set.contains(&candidate) {
            return Ok(candidate);
        }
    }
    anyhow::bail!("IP pool exhausted (all 253 IPs in use)")
}

/// Pick the lowest available VSOCK CID (3..=255).
pub fn next_available_cid(conn: &Connection) -> Result<u32> {
    let used: Vec<u32> = conn
        .prepare("SELECT vsock_cid FROM vms WHERE status != 'stopped'")?
        .query_map([], |r| r.get::<_, u32>(0))?
        .collect::<std::result::Result<_, _>>()?;

    let used_set: std::collections::HashSet<u32> = used.into_iter().collect();

    for cid in 3u32..=255 {
        if !used_set.contains(&cid) {
            return Ok(cid);
        }
    }
    anyhow::bail!("VSOCK CID pool exhausted (all 253 CIDs in use)")
}

fn row_to_vm(row: &rusqlite::Row<'_>) -> rusqlite::Result<Vm> {
    let proxy_port: i64 = row.get(14).unwrap_or(80);
    let proxy_public: i64 = row.get(15).unwrap_or(0);
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
        proxy_port: proxy_port as u16,
        proxy_public: proxy_public != 0,
        owner_id: row.get(16)?,
    })
}

/// Set the proxy port for a VM.
pub fn set_proxy_port(conn: &Connection, name: &str, port: u16) -> Result<bool> {
    let changed = conn.execute(
        "UPDATE vms SET proxy_port = ?1 WHERE name = ?2",
        params![port as i64, name],
    )?;
    Ok(changed > 0)
}

/// Set the public visibility flag for a VM.
pub fn set_proxy_public(conn: &Connection, name: &str, public: bool) -> Result<bool> {
    let changed = conn.execute(
        "UPDATE vms SET proxy_public = ?1 WHERE name = ?2",
        params![if public { 1i64 } else { 0i64 }, name],
    )?;
    Ok(changed > 0)
}

/// Update VM resources (CPU and/or memory). Only updates non-None fields.
pub fn set_vm_resources(
    conn: &Connection,
    name: &str,
    vcpus: Option<u32>,
    memory_mb: Option<u32>,
) -> Result<bool> {
    match (vcpus, memory_mb) {
        (Some(v), Some(m)) => {
            let changed = conn.execute(
                "UPDATE vms SET vcpus = ?1, memory_mb = ?2 WHERE name = ?3",
                params![v as i64, m as i64, name],
            )?;
            Ok(changed > 0)
        }
        (Some(v), None) => {
            let changed = conn.execute(
                "UPDATE vms SET vcpus = ?1 WHERE name = ?2",
                params![v as i64, name],
            )?;
            Ok(changed > 0)
        }
        (None, Some(m)) => {
            let changed = conn.execute(
                "UPDATE vms SET memory_mb = ?1 WHERE name = ?2",
                params![m as i64, name],
            )?;
            Ok(changed > 0)
        }
        (None, None) => Ok(false), // No-op if both are None
    }
}

// ── Plans & Subscriptions ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Plan {
    pub id: String,
    pub name: String,
    pub max_vms: u32,
    pub max_vcpus: u32,
    pub max_memory_mb: u32,
    pub max_disk_gb: u32,
    pub max_snapshots: u32,
    pub price_cents: u32,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: String,
    pub user_id: String,
    pub plan_id: String,
    pub status: String,
    pub created_at: String,
}

/// Aggregated live resource usage for a user (non-stopped VMs only).
#[derive(Debug, Clone, Default)]
pub struct UserUsage {
    pub vm_count: u32,
    pub total_vcpus: u32,
    pub total_memory_mb: u32,
    pub snapshot_count: u32,
}

// ── Plan queries ──────────────────────────────────────────────────────────────

pub fn list_plans(conn: &Connection) -> Result<Vec<Plan>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, max_vms, max_vcpus, max_memory_mb, max_disk_gb,
                max_snapshots, price_cents, created_at
         FROM plans ORDER BY price_cents",
    )?;
    let rows = stmt.query_map([], |r| Ok(row_to_plan(r).expect("parse plan")))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

pub fn get_plan(conn: &Connection, plan_id: &str) -> Result<Option<Plan>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, max_vms, max_vcpus, max_memory_mb, max_disk_gb,
                max_snapshots, price_cents, created_at
         FROM plans WHERE id=?1",
    )?;
    let mut rows = stmt.query(params![plan_id])?;
    Ok(rows.next()?.map(|r| row_to_plan(r).expect("parse plan")))
}

fn row_to_plan(row: &rusqlite::Row<'_>) -> rusqlite::Result<Plan> {
    Ok(Plan {
        id: row.get(0)?,
        name: row.get(1)?,
        max_vms: row.get::<_, i64>(2)? as u32,
        max_vcpus: row.get::<_, i64>(3)? as u32,
        max_memory_mb: row.get::<_, i64>(4)? as u32,
        max_disk_gb: row.get::<_, i64>(5)? as u32,
        max_snapshots: row.get::<_, i64>(6)? as u32,
        price_cents: row.get::<_, i64>(7)? as u32,
        created_at: row.get(8)?,
    })
}

// ── Subscription queries ──────────────────────────────────────────────────────

/// Get a user's subscription. Returns `None` if not yet assigned.
pub fn get_subscription(conn: &Connection, user_id: &str) -> Result<Option<Subscription>> {
    let mut stmt = conn.prepare(
        "SELECT id, user_id, plan_id, status, created_at
         FROM subscriptions WHERE user_id=?1",
    )?;
    let mut rows = stmt.query(params![user_id])?;
    Ok(rows
        .next()?
        .map(|r| row_to_subscription(r).expect("parse subscription")))
}

/// Get a user's subscription joined with their plan. Returns the effective plan
/// (defaulting to 'free' if no subscription is found).
pub fn get_user_plan(conn: &Connection, user_id: &str) -> Result<(Subscription, Plan)> {
    let sub = get_subscription(conn, user_id)?.unwrap_or_else(|| Subscription {
        id: String::new(),
        user_id: user_id.to_string(),
        plan_id: "free".to_string(),
        status: "active".to_string(),
        created_at: String::new(),
    });
    let plan = get_plan(conn, &sub.plan_id)?.unwrap_or_else(free_plan_default);
    Ok((sub, plan))
}

/// Create a subscription for a user (called at registration time).
pub fn create_subscription(
    conn: &Connection,
    user_id: &str,
    plan_id: &str,
) -> Result<Subscription> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR IGNORE INTO subscriptions (id, user_id, plan_id, status, created_at)
         VALUES (?1, ?2, ?3, 'active', ?4)",
        params![id, user_id, plan_id, now],
    )
    .context("insert subscription")?;
    Ok(Subscription {
        id,
        user_id: user_id.to_string(),
        plan_id: plan_id.to_string(),
        status: "active".to_string(),
        created_at: now,
    })
}

/// Upgrade a user to a different plan (also updates status).
pub fn set_user_plan(conn: &Connection, user_id: &str, plan_id: &str) -> Result<bool> {
    let changed = conn.execute(
        "UPDATE subscriptions SET plan_id=?1, status='active' WHERE user_id=?2",
        params![plan_id, user_id],
    )?;
    Ok(changed > 0)
}

fn row_to_subscription(row: &rusqlite::Row<'_>) -> rusqlite::Result<Subscription> {
    Ok(Subscription {
        id: row.get(0)?,
        user_id: row.get(1)?,
        plan_id: row.get(2)?,
        status: row.get(3)?,
        created_at: row.get(4)?,
    })
}

/// The free plan defaults — used as a fallback when the DB has no plan row.
fn free_plan_default() -> Plan {
    Plan {
        id: "free".to_string(),
        name: "Free".to_string(),
        max_vms: 2,
        max_vcpus: 4,
        max_memory_mb: 2048,
        max_disk_gb: 20,
        max_snapshots: 5,
        price_cents: 0,
        created_at: String::new(),
    }
}

// ── Usage queries ─────────────────────────────────────────────────────────────

/// Count a user's live resource consumption (running + starting VMs).
pub fn get_user_usage(conn: &Connection, owner_id: &str) -> Result<UserUsage> {
    let (vm_count, total_vcpus, total_memory_mb): (i64, i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(vcpus),0), COALESCE(SUM(memory_mb),0)
         FROM vms WHERE owner_id=?1 AND status != 'stopped'",
        params![owner_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let snapshot_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM snapshots
         WHERE vm_name IN (SELECT name FROM vms WHERE owner_id=?1)",
        params![owner_id],
        |r| r.get(0),
    )?;
    Ok(UserUsage {
        vm_count: vm_count as u32,
        total_vcpus: total_vcpus as u32,
        total_memory_mb: total_memory_mb as u32,
        snapshot_count: snapshot_count as u32,
    })
}

// ── Snapshots ─────────────────────────────────────────────────────────────────

/// A snapshot record stored in the database.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub id: String,
    pub vm_name: String,
    pub name: String,
    pub size_bytes: Option<u64>,
    pub created_at: String,
}

/// Insert a snapshot record.
pub fn insert_snapshot(conn: &Connection, snap: &Snapshot) -> Result<()> {
    conn.execute(
        "INSERT INTO snapshots (id, vm_name, name, size_bytes, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            snap.id,
            snap.vm_name,
            snap.name,
            snap.size_bytes.map(|s| s as i64),
            snap.created_at,
        ],
    )
    .context("insert snapshot")?;
    Ok(())
}

/// Retrieve a snapshot by VM name + snapshot name.
pub fn get_snapshot(conn: &Connection, vm_name: &str, snap_name: &str) -> Result<Option<Snapshot>> {
    let mut stmt = conn.prepare(
        "SELECT id, vm_name, name, size_bytes, created_at
         FROM snapshots WHERE vm_name=?1 AND name=?2",
    )?;
    let mut rows = stmt.query(params![vm_name, snap_name])?;
    match rows.next()? {
        None => Ok(None),
        Some(row) => Ok(Some(row_to_snapshot(row)?)),
    }
}

/// List all snapshots for a VM, ordered by creation time.
pub fn list_snapshots(conn: &Connection, vm_name: &str) -> Result<Vec<Snapshot>> {
    let mut stmt = conn.prepare(
        "SELECT id, vm_name, name, size_bytes, created_at
         FROM snapshots WHERE vm_name=?1 ORDER BY created_at",
    )?;
    let rows = stmt.query_map(params![vm_name], |row| {
        Ok(row_to_snapshot(row).expect("parse snapshot row"))
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// Count snapshots for a VM.
pub fn count_snapshots(conn: &Connection, vm_name: &str) -> Result<u32> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM snapshots WHERE vm_name=?1",
        params![vm_name],
        |r| r.get(0),
    )?;
    Ok(count as u32)
}

/// Delete a snapshot record.
pub fn delete_snapshot(conn: &Connection, vm_name: &str, snap_name: &str) -> Result<bool> {
    let changed = conn.execute(
        "DELETE FROM snapshots WHERE vm_name=?1 AND name=?2",
        params![vm_name, snap_name],
    )?;
    Ok(changed > 0)
}

/// Delete all snapshot records for a VM (called when the VM is destroyed).
pub fn delete_all_snapshots(conn: &Connection, vm_name: &str) -> Result<usize> {
    let changed = conn.execute("DELETE FROM snapshots WHERE vm_name=?1", params![vm_name])?;
    Ok(changed)
}

fn row_to_snapshot(row: &rusqlite::Row<'_>) -> rusqlite::Result<Snapshot> {
    let size_bytes: Option<i64> = row.get(3)?;
    Ok(Snapshot {
        id: row.get(0)?,
        vm_name: row.get(1)?,
        name: row.get(2)?,
        size_bytes: size_bytes.map(|s| s as u64),
        created_at: row.get(4)?,
    })
}

// ── Custom Domains ────────────────────────────────────────────────────────────

/// A custom domain record stored in the database.
#[derive(Debug, Clone)]
pub struct CustomDomain {
    pub id: String,
    pub vm_name: String,
    pub domain: String,
    pub verified: bool,
    pub created_at: String,
}

/// Add a custom domain for a VM (initially unverified).
pub fn add_custom_domain(conn: &Connection, vm_name: &str, domain: &str) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO custom_domains (id, vm_name, domain, verified, created_at)
         VALUES (?1, ?2, ?3, 0, ?4)",
        params![id, vm_name, domain, now],
    )
    .context("insert custom domain")?;
    Ok(id)
}

/// List all custom domains for a VM.
pub fn list_custom_domains(conn: &Connection, vm_name: &str) -> Result<Vec<CustomDomain>> {
    let mut stmt = conn.prepare(
        "SELECT id, vm_name, domain, verified, created_at
         FROM custom_domains WHERE vm_name = ?1 ORDER BY created_at",
    )?;
    let rows = stmt.query_map(params![vm_name], |row| {
        Ok(CustomDomain {
            id: row.get(0)?,
            vm_name: row.get(1)?,
            domain: row.get(2)?,
            verified: {
                let v: i64 = row.get(3)?;
                v != 0
            },
            created_at: row.get(4)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("list custom domains")
}

/// Look up a custom domain by domain name (to check for duplicates).
pub fn get_custom_domain_by_name(conn: &Connection, domain: &str) -> Result<Option<CustomDomain>> {
    let mut stmt = conn.prepare(
        "SELECT id, vm_name, domain, verified, created_at
         FROM custom_domains WHERE domain = ?1",
    )?;
    let mut rows = stmt.query(params![domain])?;
    match rows.next()? {
        None => Ok(None),
        Some(row) => Ok(Some(CustomDomain {
            id: row.get(0)?,
            vm_name: row.get(1)?,
            domain: row.get(2)?,
            verified: {
                let v: i64 = row.get(3)?;
                v != 0
            },
            created_at: row.get(4)?,
        })),
    }
}

/// Remove a custom domain.
pub fn remove_custom_domain(conn: &Connection, vm_name: &str, domain: &str) -> Result<bool> {
    let changed = conn.execute(
        "DELETE FROM custom_domains WHERE vm_name = ?1 AND domain = ?2",
        params![vm_name, domain],
    )?;
    Ok(changed > 0)
}

/// Mark a domain as verified (certificate provisioned successfully).
pub fn mark_domain_verified(conn: &Connection, domain: &str) -> Result<bool> {
    let changed = conn.execute(
        "UPDATE custom_domains SET verified = 1 WHERE domain = ?1",
        params![domain],
    )?;
    Ok(changed > 0)
}

/// List all verified domains (for cert renewal checks).
pub fn list_all_verified_domains(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT domain FROM custom_domains WHERE verified = 1")?;
    let rows = stmt.query_map([], |row| row.get(0))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("list verified domains")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        migrate(&conn).unwrap();
        conn
    }

    fn sample_vm(name: &str, owner_id: Option<&str>) -> Vm {
        Vm {
            name: name.to_string(),
            status: "stopped".to_string(),
            ip: format!("10.0.0.{}", name.len()),
            vsock_cid: name.len() as u32 + 3,
            ch_pid: None,
            ch_api_socket: format!("/run/minions/{name}.sock"),
            ch_vsock_socket: format!("/run/minions/{name}.vsock"),
            tap_device: format!("tap-{name}"),
            mac_address: "52:54:00:00:00:01".to_string(),
            vcpus: 2,
            memory_mb: 1024,
            rootfs_path: format!("/var/lib/minions/vms/{name}/rootfs.ext4"),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            stopped_at: None,
            proxy_port: 80,
            proxy_public: false,
            owner_id: owner_id.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_insert_and_get_with_owner() {
        let conn = test_conn();
        let vm = sample_vm("alice-vm", Some("user-alice"));
        insert_vm(&conn, &vm).unwrap();

        let found = get_vm(&conn, "alice-vm").unwrap().unwrap();
        assert_eq!(found.owner_id.as_deref(), Some("user-alice"));
    }

    #[test]
    fn test_insert_and_get_without_owner() {
        let conn = test_conn();
        let vm = sample_vm("sys-vm", None);
        insert_vm(&conn, &vm).unwrap();

        let found = get_vm(&conn, "sys-vm").unwrap().unwrap();
        assert_eq!(found.owner_id, None, "admin VM should have no owner");
    }

    #[test]
    fn test_list_vms_by_owner_filters_correctly() {
        let conn = test_conn();
        insert_vm(&conn, &sample_vm("vm1", Some("alice"))).unwrap();
        insert_vm(&conn, &sample_vm("vm2", Some("bob"))).unwrap();
        insert_vm(&conn, &sample_vm("vm3", Some("alice"))).unwrap();
        insert_vm(&conn, &sample_vm("vm4", None)).unwrap();

        let alice_vms = list_vms_by_owner(&conn, "alice").unwrap();
        assert_eq!(alice_vms.len(), 2);
        assert!(
            alice_vms
                .iter()
                .all(|v| v.owner_id.as_deref() == Some("alice"))
        );

        let bob_vms = list_vms_by_owner(&conn, "bob").unwrap();
        assert_eq!(bob_vms.len(), 1);

        // list_vms returns all
        let all = list_vms(&conn).unwrap();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn test_get_vm_owned_correct_owner() {
        let conn = test_conn();
        insert_vm(&conn, &sample_vm("owned-vm", Some("user-x"))).unwrap();

        let result = get_vm_owned(&conn, "owned-vm", "user-x").unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_get_vm_owned_wrong_owner() {
        let conn = test_conn();
        insert_vm(&conn, &sample_vm("owned-vm", Some("user-x"))).unwrap();

        let result = get_vm_owned(&conn, "owned-vm", "user-y");
        assert!(result.is_err(), "wrong owner should return Err");
    }

    #[test]
    fn test_get_vm_owned_admin_vm_rejected() {
        let conn = test_conn();
        insert_vm(&conn, &sample_vm("admin-vm", None)).unwrap();

        // Admin (owner_id=NULL) VMs are not accessible by SSH gateway users.
        let result = get_vm_owned(&conn, "admin-vm", "any-user");
        assert!(
            result.is_err(),
            "admin VM should not be accessible by SSH users"
        );
    }

    #[test]
    fn test_get_vm_owned_not_found() {
        let conn = test_conn();
        let result = get_vm_owned(&conn, "nonexistent", "user-x").unwrap();
        assert!(result.is_none());
    }

    // ── Plan / subscription tests ─────────────────────────────────────────────

    #[test]
    fn test_plans_seeded() {
        let conn = test_conn();
        let plans = list_plans(&conn).unwrap();
        assert!(plans.len() >= 2, "free and pro plans should be seeded");
        assert!(plans.iter().any(|p| p.id == "free"));
        assert!(plans.iter().any(|p| p.id == "pro"));
    }

    #[test]
    fn test_get_plan() {
        let conn = test_conn();
        let free = get_plan(&conn, "free").unwrap().unwrap();
        assert_eq!(free.name, "Free");
        assert_eq!(free.max_vms, 2);
        assert_eq!(free.price_cents, 0);

        let pro = get_plan(&conn, "pro").unwrap().unwrap();
        assert_eq!(pro.max_vms, 10);
        assert!(pro.price_cents > 0);
    }

    #[test]
    fn test_create_and_get_subscription() {
        let conn = test_conn();
        let sub = create_subscription(&conn, "user-1", "free").unwrap();
        assert_eq!(sub.plan_id, "free");
        assert_eq!(sub.status, "active");

        let fetched = get_subscription(&conn, "user-1").unwrap().unwrap();
        assert_eq!(fetched.user_id, "user-1");
        assert_eq!(fetched.plan_id, "free");
    }

    #[test]
    fn test_get_user_plan_defaults_to_free() {
        let conn = test_conn();
        // No subscription — should default to free plan.
        let (sub, plan) = get_user_plan(&conn, "nobody").unwrap();
        assert_eq!(plan.id, "free");
        assert_eq!(sub.plan_id, "free");
    }

    #[test]
    fn test_set_user_plan() {
        let conn = test_conn();
        create_subscription(&conn, "user-1", "free").unwrap();
        let upgraded = set_user_plan(&conn, "user-1", "pro").unwrap();
        assert!(upgraded);

        let (_, plan) = get_user_plan(&conn, "user-1").unwrap();
        assert_eq!(plan.id, "pro");
    }

    #[test]
    fn test_get_user_usage() {
        let conn = test_conn();

        // Insert two running VMs owned by user-1.
        let mut vm1 = sample_vm("vm1", Some("user-1"));
        vm1.status = "running".to_string();
        vm1.vcpus = 2;
        vm1.memory_mb = 512;
        insert_vm(&conn, &vm1).unwrap();

        let mut vm2 = sample_vm("vm2", Some("user-1"));
        vm2.status = "running".to_string();
        vm2.ip = "10.0.0.20".to_string();
        vm2.vsock_cid = 20;
        vm2.vcpus = 4;
        vm2.memory_mb = 1024;
        insert_vm(&conn, &vm2).unwrap();

        // A stopped VM — should NOT count toward usage.
        let mut vm3 = sample_vm("vm3", Some("user-1"));
        vm3.status = "stopped".to_string();
        vm3.ip = "10.0.0.21".to_string();
        vm3.vsock_cid = 21;
        vm3.vcpus = 8;
        vm3.memory_mb = 8192;
        insert_vm(&conn, &vm3).unwrap();

        // A VM owned by someone else — should NOT count.
        let mut vm4 = sample_vm("vm4", Some("user-2"));
        vm4.status = "running".to_string();
        vm4.ip = "10.0.0.22".to_string();
        vm4.vsock_cid = 22;
        vm4.vcpus = 1;
        vm4.memory_mb = 256;
        insert_vm(&conn, &vm4).unwrap();

        let usage = get_user_usage(&conn, "user-1").unwrap();
        assert_eq!(usage.vm_count, 2);
        assert_eq!(usage.total_vcpus, 6); // 2 + 4
        assert_eq!(usage.total_memory_mb, 1536); // 512 + 1024
    }

    // ── Snapshot tests ────────────────────────────────────────────────────────

    fn sample_snapshot(vm_name: &str, snap_name: &str) -> Snapshot {
        Snapshot {
            id: format!("{vm_name}-{snap_name}-id"),
            vm_name: vm_name.to_string(),
            name: snap_name.to_string(),
            size_bytes: Some(1024 * 1024 * 500), // 500 MB
            created_at: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_snapshot_insert_and_get() {
        let conn = test_conn();
        let snap = sample_snapshot("myvm", "snap1");
        insert_snapshot(&conn, &snap).unwrap();

        let found = get_snapshot(&conn, "myvm", "snap1").unwrap().unwrap();
        assert_eq!(found.vm_name, "myvm");
        assert_eq!(found.name, "snap1");
        assert_eq!(found.size_bytes, Some(1024 * 1024 * 500));
    }

    #[test]
    fn test_snapshot_list_and_count() {
        let conn = test_conn();
        insert_snapshot(&conn, &sample_snapshot("myvm", "a")).unwrap();
        insert_snapshot(&conn, &sample_snapshot("myvm", "b")).unwrap();
        insert_snapshot(&conn, &sample_snapshot("othervm", "x")).unwrap();

        let snaps = list_snapshots(&conn, "myvm").unwrap();
        assert_eq!(snaps.len(), 2);

        let count = count_snapshots(&conn, "myvm").unwrap();
        assert_eq!(count, 2);

        let other_count = count_snapshots(&conn, "othervm").unwrap();
        assert_eq!(other_count, 1);
    }

    #[test]
    fn test_snapshot_delete() {
        let conn = test_conn();
        insert_snapshot(&conn, &sample_snapshot("myvm", "snap1")).unwrap();
        insert_snapshot(&conn, &sample_snapshot("myvm", "snap2")).unwrap();

        let deleted = delete_snapshot(&conn, "myvm", "snap1").unwrap();
        assert!(deleted);

        let remaining = list_snapshots(&conn, "myvm").unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].name, "snap2");

        // Deleting non-existent snapshot returns false.
        let not_found = delete_snapshot(&conn, "myvm", "gone").unwrap();
        assert!(!not_found);
    }

    #[test]
    fn test_snapshot_unique_constraint() {
        let conn = test_conn();
        insert_snapshot(&conn, &sample_snapshot("myvm", "snap1")).unwrap();
        // Inserting same (vm_name, name) should fail.
        let result = insert_snapshot(&conn, &sample_snapshot("myvm", "snap1"));
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_all_snapshots() {
        let conn = test_conn();
        insert_snapshot(&conn, &sample_snapshot("myvm", "a")).unwrap();
        insert_snapshot(&conn, &sample_snapshot("myvm", "b")).unwrap();
        insert_snapshot(&conn, &sample_snapshot("othervm", "x")).unwrap();

        let deleted = delete_all_snapshots(&conn, "myvm").unwrap();
        assert_eq!(deleted, 2);

        assert_eq!(list_snapshots(&conn, "myvm").unwrap().len(), 0);
        assert_eq!(list_snapshots(&conn, "othervm").unwrap().len(), 1);
    }
}
