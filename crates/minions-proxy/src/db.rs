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

#[derive(Debug, Clone)]
pub struct CustomDomain {
    pub id: String,
    pub vm_name: String,
    pub domain: String,
    pub verified: bool,
    pub created_at: String,
}

// ── Migration ─────────────────────────────────────────────────────────────────

/// Add proxy columns to `vms` if they don't exist yet.
pub fn migrate(conn: &Connection) -> Result<()> {
    // SQLite returns an error if you ADD a column that already exists.
    // We ignore those errors so this is safe to run repeatedly.
    let _ =
        conn.execute_batch("ALTER TABLE vms ADD COLUMN proxy_port   INTEGER NOT NULL DEFAULT 80;");
    let _ =
        conn.execute_batch("ALTER TABLE vms ADD COLUMN proxy_public  INTEGER NOT NULL DEFAULT 0;");

    // Create custom_domains table for user-provided domains
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS custom_domains (
            id          TEXT PRIMARY KEY,
            vm_name     TEXT NOT NULL,
            domain      TEXT UNIQUE NOT NULL,
            verified    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL
        );",
    )
    .context("create custom_domains table")?;

    Ok(())
}

// ── Open ──────────────────────────────────────────────────────────────────────

pub fn open(path: &str) -> Result<Connection> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path).context("open sqlite db")?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .context("WAL")?;
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

// ── Custom Domains ────────────────────────────────────────────────────────────

/// Look up a VM by custom domain. Returns None if domain not found or not verified.
pub fn get_vm_by_custom_domain(conn: &Connection, domain: &str) -> Result<Option<VmProxy>> {
    let mut stmt = conn.prepare(
        "SELECT v.name, v.status, v.ip, v.proxy_port, v.proxy_public
         FROM vms v
         JOIN custom_domains d ON d.vm_name = v.name
         WHERE d.domain = ?1 AND d.verified = 1",
    )?;
    let mut rows = stmt.query(params![domain])?;
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

/// Add a custom domain for a VM.
pub fn add_custom_domain(conn: &Connection, vm_name: &str, domain: &str) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
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
