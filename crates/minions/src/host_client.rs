//! HTTP client for communicating with remote node agents.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Client for calling a remote node agent API.
pub struct HostClient {
    base_url: String,
    client: reqwest::Client,
}

impl HostClient {
    pub fn new(address: &str, port: u16) -> Self {
        let base_url = format!("http://{}:{}", address, port);
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    pub async fn create_vm(
        &self,
        name: &str,
        vcpus: u32,
        memory_mb: u32,
        ssh_pubkey: Option<String>,
        owner_id: Option<String>,
    ) -> Result<serde_json::Value> {
        #[derive(Serialize)]
        struct CreateRequest {
            name: String,
            vcpus: u32,
            memory_mb: u32,
            ssh_pubkey: Option<String>,
            owner_id: Option<String>,
        }

        let req = CreateRequest {
            name: name.to_string(),
            vcpus,
            memory_mb,
            ssh_pubkey,
            owner_id,
        };

        let resp = self
            .client
            .post(format!("{}/vms", self.base_url))
            .json(&req)
            .send()
            .await
            .context("send create_vm request")?
            .error_for_status()
            .context("create_vm request failed")?;

        resp.json().await.context("parse create_vm response")
    }

    pub async fn destroy_vm(&self, name: &str) -> Result<()> {
        self.client
            .delete(format!("{}/vms/{}", self.base_url, name))
            .send()
            .await
            .context("send destroy_vm request")?
            .error_for_status()
            .context("destroy_vm request failed")?;
        Ok(())
    }

    pub async fn stop_vm(&self, name: &str) -> Result<serde_json::Value> {
        let resp = self
            .client
            .post(format!("{}/vms/{}/stop", self.base_url, name))
            .send()
            .await
            .context("send stop_vm request")?
            .error_for_status()
            .context("stop_vm request failed")?;

        resp.json().await.context("parse stop_vm response")
    }

    pub async fn start_vm(&self, name: &str) -> Result<serde_json::Value> {
        let resp = self
            .client
            .post(format!("{}/vms/{}/start", self.base_url, name))
            .send()
            .await
            .context("send start_vm request")?
            .error_for_status()
            .context("start_vm request failed")?;

        resp.json().await.context("parse start_vm response")
    }

    pub async fn restart_vm(&self, name: &str) -> Result<serde_json::Value> {
        let resp = self
            .client
            .post(format!("{}/vms/{}/restart", self.base_url, name))
            .send()
            .await
            .context("send restart_vm request")?
            .error_for_status()
            .context("restart_vm request failed")?;

        resp.json().await.context("parse restart_vm response")
    }

    pub async fn snapshot_vm(
        &self,
        vm_name: &str,
        snap_name: Option<String>,
    ) -> Result<serde_json::Value> {
        #[derive(Serialize)]
        struct SnapshotRequest {
            name: Option<String>,
        }

        let req = SnapshotRequest { name: snap_name };

        let resp = self
            .client
            .post(format!("{}/vms/{}/snapshot", self.base_url, vm_name))
            .json(&req)
            .send()
            .await
            .context("send snapshot request")?
            .error_for_status()
            .context("snapshot request failed")?;

        resp.json().await.context("parse snapshot response")
    }

    pub async fn exec_vm(
        &self,
        name: &str,
        command: String,
        args: Vec<String>,
    ) -> Result<serde_json::Value> {
        #[derive(Serialize)]
        struct ExecRequest {
            command: String,
            args: Vec<String>,
        }

        let req = ExecRequest { command, args };

        let resp = self
            .client
            .post(format!("{}/vms/{}/exec", self.base_url, name))
            .json(&req)
            .send()
            .await
            .context("send exec request")?
            .error_for_status()
            .context("exec request failed")?;

        resp.json().await.context("parse exec response")
    }

    pub async fn status(&self) -> Result<HostStatus> {
        let resp = self
            .client
            .get(format!("{}/status", self.base_url))
            .send()
            .await
            .context("send status request")?
            .error_for_status()
            .context("status request failed")?;

        resp.json().await.context("parse status response")
    }
}

#[derive(Debug, Deserialize)]
pub struct HostStatus {
    pub total_vcpus: u32,
    pub total_memory_mb: u32,
    pub total_disk_gb: u32,
    pub available_vcpus: u32,
    pub available_memory_mb: u32,
    pub available_disk_gb: u32,
    pub vm_count: usize,
}
