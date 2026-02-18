//! User and SSH key management for the SSH gateway.
//!
//! Uses the same SQLite file as the main daemon (`/var/lib/minions/state.db`).
//! Adds two extra tables (`users`, `ssh_keys`) that only the SSH gateway touches.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct SshKey {
    pub id: String,
    pub user_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub name: String,
    pub created_at: String,
}

// ── Migration ─────────────────────────────────────────────────────────────────

/// Ensure the SSH gateway tables exist.
/// Call this once at gateway startup (after the main daemon has run its migrations).
pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS users (
            id          TEXT PRIMARY KEY,
            email       TEXT UNIQUE NOT NULL,
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ssh_keys (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            public_key  TEXT NOT NULL,
            fingerprint TEXT UNIQUE NOT NULL,
            name        TEXT NOT NULL DEFAULT 'default',
            created_at  TEXT NOT NULL
        );
        ",
    )
    .context("ssh gateway migration")
}

// ── Open ──────────────────────────────────────────────────────────────────────

pub fn open(path: &str) -> Result<Connection> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create db dir {:?}", parent))?;
    }
    let conn = Connection::open(path).context("open sqlite db")?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
        .context("set pragmas")?;
    migrate(&conn)?;
    Ok(conn)
}

// ── User operations ───────────────────────────────────────────────────────────

/// Look up a registered user by SSH key fingerprint.
pub fn get_user_by_fingerprint(conn: &Connection, fingerprint: &str) -> Result<Option<User>> {
    let mut stmt = conn.prepare(
        "SELECT u.id, u.email, u.created_at
         FROM users u
         JOIN ssh_keys k ON k.user_id = u.id
         WHERE k.fingerprint = ?1",
    )?;
    let mut rows = stmt.query(params![fingerprint])?;
    match rows.next()? {
        Some(row) => Ok(Some(User {
            id: row.get(0)?,
            email: row.get(1)?,
            created_at: row.get(2)?,
        })),
        None => Ok(None),
    }
}

/// Create a new user, associating their SSH public key.
pub fn create_user(
    conn: &Connection,
    email: &str,
    public_key: &str,
    fingerprint: &str,
) -> Result<User> {
    let user_id = uuid::Uuid::new_v4().to_string();
    let key_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute(
        "INSERT INTO users (id, email, created_at) VALUES (?1, ?2, ?3)",
        params![user_id, email, now],
    )
    .context("insert user")?;

    conn.execute(
        "INSERT INTO ssh_keys (id, user_id, public_key, fingerprint, name, created_at)
         VALUES (?1, ?2, ?3, ?4, 'default', ?5)",
        params![key_id, user_id, public_key, fingerprint, now],
    )
    .context("insert ssh key")?;

    Ok(User { id: user_id, email: email.to_string(), created_at: now })
}

/// Get a user by their ID.
pub fn get_user(conn: &Connection, id: &str) -> Result<Option<User>> {
    let mut stmt =
        conn.prepare("SELECT id, email, created_at FROM users WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    match rows.next()? {
        Some(row) => Ok(Some(User {
            id: row.get(0)?,
            email: row.get(1)?,
            created_at: row.get(2)?,
        })),
        None => Ok(None),
    }
}

/// List all SSH keys for a user.
pub fn list_ssh_keys(conn: &Connection, user_id: &str) -> Result<Vec<SshKey>> {
    let mut stmt = conn.prepare(
        "SELECT id, user_id, public_key, fingerprint, name, created_at
         FROM ssh_keys WHERE user_id = ?1 ORDER BY created_at",
    )?;
    let rows = stmt.query_map(params![user_id], |row| {
        Ok(SshKey {
            id: row.get(0)?,
            user_id: row.get(1)?,
            public_key: row.get(2)?,
            fingerprint: row.get(3)?,
            name: row.get(4)?,
            created_at: row.get(5)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().context("list ssh keys")
}

/// Add an additional SSH key to an existing user.
pub fn add_ssh_key(
    conn: &Connection,
    user_id: &str,
    public_key: &str,
    fingerprint: &str,
    name: &str,
) -> Result<SshKey> {
    let key_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO ssh_keys (id, user_id, public_key, fingerprint, name, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![key_id, user_id, public_key, fingerprint, name, now],
    )
    .context("insert ssh key")?;
    Ok(SshKey {
        id: key_id,
        user_id: user_id.to_string(),
        public_key: public_key.to_string(),
        fingerprint: fingerprint.to_string(),
        name: name.to_string(),
        created_at: now,
    })
}

/// Remove an SSH key by fingerprint (only if it belongs to the given user).
pub fn remove_ssh_key(conn: &Connection, user_id: &str, fingerprint: &str) -> Result<bool> {
    let changed = conn.execute(
        "DELETE FROM ssh_keys WHERE user_id = ?1 AND fingerprint = ?2",
        params![user_id, fingerprint],
    )?;
    Ok(changed > 0)
}
