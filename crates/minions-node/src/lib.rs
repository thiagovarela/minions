//! Node agent library — VM lifecycle management on a single host.
//!
//! This crate provides both:
//! - A library API for in-process use by the control plane (single-host deployments)
//! - A standalone binary (`minions-node`) for remote host agents (multi-host deployments)

pub mod agent;
pub mod hypervisor;
pub mod network;
pub mod storage;
pub mod vm;

// Re-export db for convenience
pub use minions_db as db;

// Re-export commonly used types
pub use vm::{
    check_quota, copy, create, destroy, list, list_snapshots, rename, resize, restart, restore_snapshot,
    snapshot, start, stop, delete_snapshot, MAX_SNAPSHOTS_PER_VM,
};
