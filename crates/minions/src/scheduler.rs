//! VM placement scheduler — chooses which host to create a VM on.

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::db;

#[derive(Debug, Clone, Copy)]
pub enum Strategy {
    /// Fill hosts before spreading (maximize utilization).
    BinPack,
    /// Distribute evenly (maximize fault tolerance).
    Spread,
}

/// Schedule a VM placement based on requested resources.
///
/// Returns the host ID where the VM should be created.
pub fn schedule(
    conn: &Connection,
    requested_vcpus: u32,
    requested_memory_mb: u32,
    _strategy: Strategy,
) -> Result<String> {
    let hosts = db::list_hosts(conn).context("list hosts for scheduling")?;

    // Filter out offline hosts and hosts without enough capacity.
    let mut candidates: Vec<_> = hosts
        .into_iter()
        .filter(|h| h.status == "active")
        .filter(|h| {
            h.available_vcpus >= requested_vcpus && h.available_memory_mb >= requested_memory_mb
        })
        .collect();

    if candidates.is_empty() {
        anyhow::bail!(
            "No host has enough capacity for {} vCPUs / {} MB memory",
            requested_vcpus,
            requested_memory_mb
        );
    }

    // For now, always use bin-pack strategy (sort by available capacity ascending).
    // TODO: Implement spread strategy
    candidates.sort_by_key(|h| h.available_vcpus);

    Ok(candidates[0].id.clone())
}
