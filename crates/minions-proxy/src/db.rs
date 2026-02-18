//! DB helpers for the HTTPS proxy — VM lookup with proxy fields.
//!
//! Runs the migration that adds `proxy_port` and `proxy_public` to the `vms`
//! table (safe to run multiple times; SQLite ignores duplicate column errors).

use anyhow::{Context, Result};
use rusqlite::{Connection, params};

#[derive(Debug, Clone)]
pub struct VmProxy {
    pub name: String,
    pub status: String,
    pub ip: String,
    /// Port the VM's web service listens on (default 80).
    pub proxy_port: u16,
    /// Whether the VM is publicly accessible without auth.
    pub proxy_public: bool,
}

// ── Migration ─────────────────────────────────────────────────────────────────

/// Add proxy columns to `vms` if they don't exist yet.
pub fn migrate(conn: &Connection) -> Result<()> {
    // SQLite returns an error if you ADD a column that already exists.
    // We ignore those errors so this is safe to run repeatedly.
    let _ = conn.execute_batch(
        "ALTER TABLE vms ADD COLUMN proxy_port   INTEGER NOT NULL DEFAULT 80;",
    );
    let _ = conn.execute_batch(
        "ALTER TABLE vms ADD COLUMN proxy_public  INTEGER NOT NULL DEFAULT 0;",
    );
    Ok(())
}

// ── Open ──────────────────────────────────────────────────────────────────────

pub fn open(path: &str) -> Result<Connection> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path).context("open sqlite db")?;
    conn.execute_batch("PRAGMA journal_mode=WAL;").context("WAL")?;
    migrate(&conn)?;
    Ok(conn)
}

// ── Queries ───────────────────────────────────────────────────────────────────

/// Look up a VM by subdomain name. Returns `None` if not found or not running.
pub fn get_vm_proxy(conn: &Connection, name: &str) -> Result<Option<VmProxy>> {
    let mut stmt = conn.prepare(
        "SELECT name, status, ip, proxy_port, proxy_public
         FROM vms WHERE name = ?1",
    )?;
    let mut rows = stmt.query(params![name])?;
    match rows.next()? {
        None => Ok(None),
        Some(row) => Ok(Some(VmProxy {
            name: row.get(0)?,
            status: row.get(1)?,
            ip: row.get(2)?,
            proxy_port: {
                let p: i64 = row.get(3)?;
                p as u16
            },
            proxy_public: {
                let v: i64 = row.get(4)?;
                v != 0
            },
        })),
    }
}

/// Update the proxy port for a VM.
pub fn set_proxy_port(conn: &Connection, name: &str, port: u16) -> Result<bool> {
    let changed = conn.execute(
        "UPDATE vms SET proxy_port = ?1 WHERE name = ?2",
        params![port as i64, name],
    )?;
    Ok(changed > 0)
}

/// Set a VM to public (no auth required).
pub fn set_proxy_public(conn: &Connection, name: &str, public: bool) -> Result<bool> {
    let changed = conn.execute(
        "UPDATE vms SET proxy_public = ?1 WHERE name = ?2",
        params![if public { 1i64 } else { 0i64 }, name],
    )?;
    Ok(changed > 0)
}
