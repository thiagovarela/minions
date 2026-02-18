//! HTTP client for the remote CLI mode.
//!
//! When `--host` is given, the CLI sends requests to the minions daemon
//! instead of orchestrating VMs directly.
//!
//! Authentication: if `MINIONS_API_KEY` is set in the environment, all
//! requests carry `Authorization: Bearer <key>`.  The `--api-key` flag
//! can also be used to supply the key explicitly (it takes precedence).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct CreateRequest {
    pub name: String,
    pub cpus: u32,
    pub memory_mb: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VmResponse {
    pub name: String,
    pub status: String,
    pub ip: String,
    pub vsock_cid: u32,
    pub cpus: u32,
    pub memory_mb: u32,
    pub pid: Option<i64>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ExecRequest {
    pub command: String,
    pub args: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub struct Client {
    http: reqwest::Client,
    base: String,
    /// Bearer token attached to every request (if set).
    api_key: Option<String>,
}

impl Client {
    /// Create a new client.
    ///
    /// `api_key` is taken from (in priority order):
    /// 1. The `api_key` argument (e.g. from `--api-key` CLI flag)
    /// 2. The `MINIONS_API_KEY` environment variable
    pub fn new(host: &str, api_key: Option<String>) -> Self {
        let base = host.trim_end_matches('/').to_string();
        let resolved_key = api_key.or_else(|| std::env::var("MINIONS_API_KEY").ok());
        Client {
            http: reqwest::Client::new(),
            base,
            api_key: resolved_key,
        }
    }

    /// Attach the Bearer token to a request builder, if we have one.
    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref key) = self.api_key {
            req.bearer_auth(key)
        } else {
            req
        }
    }

    pub async fn create_vm(&self, req: CreateRequest) -> Result<VmResponse> {
        self.auth(self.http.post(format!("{}/api/vms", self.base)).json(&req))
            .send()
            .await
            .context("send create request")?
            .error_for_status()
            .context("create VM")?
            .json()
            .await
            .context("decode create response")
    }

    pub async fn list_vms(&self) -> Result<Vec<VmResponse>> {
        self.auth(self.http.get(format!("{}/api/vms", self.base)))
            .send()
            .await
            .context("send list request")?
            .error_for_status()
            .context("list VMs")?
            .json()
            .await
            .context("decode list response")
    }

    pub async fn destroy_vm(&self, name: &str) -> Result<()> {
        self.auth(self.http.delete(format!("{}/api/vms/{name}", self.base)))
            .send()
            .await
            .context("send destroy request")?
            .error_for_status()
            .context("destroy VM")?;
        Ok(())
    }

    pub async fn start_vm(&self, name: &str) -> Result<VmResponse> {
        self.auth(self.http.post(format!("{}/api/vms/{name}/start", self.base)))
            .send()
            .await
            .context("send start request")?
            .error_for_status()
            .context("start VM")?
            .json()
            .await
            .context("decode start response")
    }

    pub async fn stop_vm(&self, name: &str) -> Result<VmResponse> {
        self.auth(self.http.post(format!("{}/api/vms/{name}/stop", self.base)))
            .send()
            .await
            .context("send stop request")?
            .error_for_status()
            .context("stop VM")?
            .json()
            .await
            .context("decode stop response")
    }

    pub async fn restart_vm(&self, name: &str) -> Result<VmResponse> {
        self.auth(self.http.post(format!("{}/api/vms/{name}/restart", self.base)))
            .send()
            .await
            .context("send restart request")?
            .error_for_status()
            .context("restart VM")?
            .json()
            .await
            .context("decode restart response")
    }

    pub async fn rename_vm(&self, name: &str, new_name: &str) -> Result<()> {
        self.auth(
            self.http
                .post(format!("{}/api/vms/{name}/rename", self.base))
                .json(&serde_json::json!({ "new_name": new_name })),
        )
        .send()
        .await
        .context("send rename request")?
        .error_for_status()
        .context("rename VM")?;
        Ok(())
    }

    pub async fn copy_vm(&self, name: &str, new_name: &str) -> Result<VmResponse> {
        self.auth(
            self.http
                .post(format!("{}/api/vms/{name}/copy", self.base))
                .json(&serde_json::json!({ "new_name": new_name })),
        )
        .send()
        .await
        .context("send copy request")?
        .error_for_status()
        .context("copy VM")?
        .json()
        .await
        .context("decode copy response")
    }

    pub async fn exec_vm(&self, name: &str, req: ExecRequest) -> Result<ExecResponse> {
        self.auth(
            self.http
                .post(format!("{}/api/vms/{name}/exec", self.base))
                .json(&req),
        )
        .send()
        .await
        .context("send exec request")?
        .error_for_status()
        .context("exec in VM")?
        .json()
        .await
        .context("decode exec response")
    }

    pub async fn vm_status(&self, name: &str) -> Result<serde_json::Value> {
        self.auth(self.http.get(format!("{}/api/vms/{name}/status", self.base)))
            .send()
            .await
            .context("send status request")?
            .error_for_status()
            .context("VM status")?
            .json()
            .await
            .context("decode status response")
    }

    pub async fn vm_logs(&self, name: &str) -> Result<String> {
        self.auth(self.http.get(format!("{}/api/vms/{name}/logs", self.base)))
            .send()
            .await
            .context("send logs request")?
            .error_for_status()
            .context("VM logs")?
            .text()
            .await
            .context("decode logs response")
    }
}

/// Response type for snapshot API calls.
#[derive(Debug, Deserialize, Serialize)]
pub struct SnapshotResponse {
    pub id: String,
    pub vm_name: String,
    pub name: String,
    pub size_bytes: Option<u64>,
    pub created_at: String,
}

impl Client {
    pub async fn create_snapshot(&self, vm: &str, name: Option<String>) -> Result<SnapshotResponse> {
        self.auth(
            self.http
                .post(format!("{}/api/vms/{vm}/snapshots", self.base))
                .json(&serde_json::json!({ "name": name })),
        )
        .send()
        .await
        .context("send create snapshot request")?
        .error_for_status()
        .context("create snapshot")?
        .json()
        .await
        .context("decode snapshot response")
    }

    pub async fn list_snapshots(&self, vm: &str) -> Result<Vec<SnapshotResponse>> {
        self.auth(self.http.get(format!("{}/api/vms/{vm}/snapshots", self.base)))
            .send()
            .await
            .context("send list snapshots request")?
            .error_for_status()
            .context("list snapshots")?
            .json()
            .await
            .context("decode snapshots response")
    }

    pub async fn restore_snapshot(&self, vm: &str, snapshot: &str) -> Result<()> {
        self.auth(
            self.http
                .post(format!("{}/api/vms/{vm}/snapshots/{snapshot}/restore", self.base)),
        )
        .send()
        .await
        .context("send restore snapshot request")?
        .error_for_status()
        .context("restore snapshot")?;
        Ok(())
    }

    pub async fn delete_snapshot(&self, vm: &str, snapshot: &str) -> Result<()> {
        self.auth(
            self.http
                .delete(format!("{}/api/vms/{vm}/snapshots/{snapshot}", self.base)),
        )
        .send()
        .await
        .context("send delete snapshot request")?
        .error_for_status()
        .context("delete snapshot")?;
        Ok(())
    }
}

/// Check if the local daemon is reachable on port 3000.
pub async fn local_daemon_url() -> Option<String> {
    let url = "http://127.0.0.1:3000";
    let client = reqwest::Client::new();
    match tokio::time::timeout(
        std::time::Duration::from_millis(200),
        client.get(format!("{url}/api/vms")).send(),
    )
    .await
    {
        Ok(Ok(_)) => Some(url.to_string()),
        _ => None,
    }
}
