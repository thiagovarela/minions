//! HTTP client for the remote CLI mode.
//!
//! When `--host` is given, the CLI sends requests to the minions daemon
//! instead of orchestrating VMs directly.

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
}

impl Client {
    pub fn new(host: &str) -> Self {
        let base = host.trim_end_matches('/').to_string();
        Client {
            http: reqwest::Client::new(),
            base,
        }
    }

    pub async fn create_vm(&self, req: CreateRequest) -> Result<VmResponse> {
        self.http
            .post(format!("{}/api/vms", self.base))
            .json(&req)
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
        self.http
            .get(format!("{}/api/vms", self.base))
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
        self.http
            .delete(format!("{}/api/vms/{name}", self.base))
            .send()
            .await
            .context("send destroy request")?
            .error_for_status()
            .context("destroy VM")?;
        Ok(())
    }

    pub async fn exec_vm(&self, name: &str, req: ExecRequest) -> Result<ExecResponse> {
        self.http
            .post(format!("{}/api/vms/{name}/exec", self.base))
            .json(&req)
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
        self.http
            .get(format!("{}/api/vms/{name}/status", self.base))
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
        self.http
            .get(format!("{}/api/vms/{name}/logs", self.base))
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
