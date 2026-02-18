//! Command-mode routing for the SSH gateway.
//!
//! Parses the command string the user typed (e.g. `ls`, `new myvm --cpus 2`)
//! and calls the local minions HTTP API.
//!
//! ## Multi-tenancy
//!
//! Every VM-mutating command first calls `check_owns()`, which fetches the VM
//! from the API and verifies that its `owner_id` matches the authenticated
//! user's ID.  Users can only see and operate on their own VMs.
//! Admin access (direct API key) bypasses this and can reach all VMs.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::db::User;

// ── HTTP client wrapper ───────────────────────────────────────────────────────

pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl ApiClient {
    pub fn new(base_url: String, api_key: Option<String>) -> Self {
        Self { client: reqwest::Client::new(), base_url, api_key }
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(key) = &self.api_key {
            req.bearer_auth(key)
        } else {
            req
        }
    }

    /// List VMs owned by `owner_id`. The SSH gateway always passes the
    /// authenticated user's ID so users only see their own VMs.
    pub async fn list_vms(&self, owner_id: &str) -> Result<Vec<VmInfo>> {
        let url = format!("{}/api/vms?owner_id={}", self.base_url, owner_id);
        let resp = self
            .auth(self.client.get(url))
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<VmInfo>>()
            .await?;
        Ok(resp)
    }

    /// Fetch a single VM by name (returns all fields including owner_id).
    pub async fn get_vm(&self, name: &str) -> Result<Option<VmInfo>> {
        let resp = self
            .auth(self.client.get(format!("{}/api/vms/{}", self.base_url, name)))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.json::<VmInfo>().await?))
    }

    /// Create a VM owned by `owner_id`.
    pub async fn create_vm(
        &self,
        name: &str,
        cpus: u32,
        memory_mb: u32,
        owner_id: &str,
    ) -> Result<VmInfo> {
        #[derive(Serialize)]
        struct Req<'a> {
            name: &'a str,
            cpus: u32,
            memory_mb: u32,
            owner_id: &'a str,
        }
        let resp = self
            .auth(
                self.client
                    .post(format!("{}/api/vms", self.base_url))
                    .json(&Req { name, cpus, memory_mb, owner_id }),
            )
            .send()
            .await?
            .error_for_status()?
            .json::<VmInfo>()
            .await?;
        Ok(resp)
    }

    pub async fn destroy_vm(&self, name: &str) -> Result<()> {
        self.auth(self.client.delete(format!("{}/api/vms/{}", self.base_url, name)))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn stop_vm(&self, name: &str) -> Result<VmInfo> {
        let resp = self
            .auth(self.client.post(format!("{}/api/vms/{}/stop", self.base_url, name)))
            .send()
            .await?
            .error_for_status()?
            .json::<VmInfo>()
            .await?;
        Ok(resp)
    }

    pub async fn restart_vm(&self, name: &str) -> Result<VmInfo> {
        let resp = self
            .auth(self.client.post(format!("{}/api/vms/{}/restart", self.base_url, name)))
            .send()
            .await?
            .error_for_status()?
            .json::<VmInfo>()
            .await?;
        Ok(resp)
    }

    pub async fn rename_vm(&self, name: &str, new_name: &str) -> Result<()> {
        #[derive(Serialize)]
        struct Req<'a> { new_name: &'a str }
        self.auth(
            self.client
                .post(format!("{}/api/vms/{}/rename", self.base_url, name))
                .json(&Req { new_name }),
        )
        .send()
        .await?
        .error_for_status()?;
        Ok(())
    }

    /// Copy a VM; the copy is owned by `owner_id`.
    pub async fn copy_vm(&self, name: &str, new_name: &str, owner_id: &str) -> Result<VmInfo> {
        #[derive(Serialize)]
        struct Req<'a> {
            new_name: &'a str,
            owner_id: &'a str,
        }
        let resp = self
            .auth(
                self.client
                    .post(format!("{}/api/vms/{}/copy", self.base_url, name))
                    .json(&Req { new_name, owner_id }),
            )
            .send()
            .await?
            .error_for_status()?
            .json::<VmInfo>()
            .await?;
        Ok(resp)
    }

    pub async fn expose_vm(&self, name: &str, port: u16) -> Result<()> {
        #[derive(Serialize)]
        struct Req { port: u16 }
        self.auth(
            self.client
                .post(format!("{}/api/vms/{}/expose", self.base_url, name))
                .json(&Req { port }),
        )
        .send()
        .await?
        .error_for_status()?;
        Ok(())
    }

    pub async fn set_vm_public(&self, name: &str) -> Result<()> {
        self.auth(self.client.post(format!("{}/api/vms/{}/set-public", self.base_url, name)))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn set_vm_private(&self, name: &str) -> Result<()> {
        self.auth(self.client.post(format!("{}/api/vms/{}/set-private", self.base_url, name)))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

// ── VmInfo ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct VmInfo {
    pub name: String,
    pub status: String,
    pub ip: String,
    pub cpus: u32,
    pub memory_mb: u32,
    pub pid: Option<i64>,
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    #[serde(default)]
    pub proxy_public: bool,
    /// The SSH gateway user who owns this VM, or None for admin-created VMs.
    pub owner_id: Option<String>,
}

fn default_proxy_port() -> u16 { 80 }

// ── Ownership enforcement ─────────────────────────────────────────────────────

/// Fetch a VM and verify it is owned by `user`.
///
/// Returns the VM on success. Errors with a user-facing message if the VM
/// does not exist or belongs to a different user.
async fn check_owns<'a>(api: &ApiClient, name: &str, user: &User) -> Result<VmInfo> {
    match api.get_vm(name).await? {
        None => bail!("VM '{}' not found\r\n", name),
        Some(vm) => {
            match &vm.owner_id {
                Some(oid) if oid == &user.id => Ok(vm),
                _ => bail!("VM '{}' not found\r\n", name), // intentionally vague — don't leak existence
            }
        }
    }
}

// ── Command execution ──────────────────────────────────────────────────────────

/// Execute a command string on behalf of `user`, returning output to send
/// back to the SSH client. Returns `(output, exit_code)`.
pub async fn run(
    cmd_str: &str,
    user: &User,
    api: &ApiClient,
    db_path: &str,
) -> (String, u32) {
    match execute(cmd_str, user, api, db_path).await {
        Ok(output) => (output, 0),
        Err(e) => (format!("error: {}\r\n", e), 1),
    }
}

async fn execute(
    cmd_str: &str,
    user: &User,
    api: &ApiClient,
    db_path: &str,
) -> Result<String> {
    let parts: Vec<&str> = cmd_str.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(help());
    }

    match parts[0] {
        // ── ls / list ──────────────────────────────────────────────────────
        // Only shows VMs owned by the authenticated user.
        "ls" | "list" => {
            let vms = api.list_vms(&user.id).await?;
            if vms.is_empty() {
                return Ok("no VMs\r\n".to_string());
            }
            let mut out = format!(
                "{:<12} {:<10} {:<16} {:>5} {:>10}  {:>5}  {:<8}\r\n",
                "NAME", "STATUS", "IP", "CPUS", "MEMORY", "PORT", "ACCESS"
            );
            out.push_str(&"-".repeat(75));
            out.push_str("\r\n");
            for vm in &vms {
                let access = if vm.proxy_public { "public" } else { "private" };
                out.push_str(&format!(
                    "{:<12} {:<10} {:<16} {:>5} {:>8} MiB  {:>5}  {:<8}\r\n",
                    vm.name, vm.status, vm.ip, vm.cpus, vm.memory_mb,
                    vm.proxy_port, access,
                ));
            }
            Ok(out)
        }

        // ── new ────────────────────────────────────────────────────────────
        // Created VM is owned by the authenticated user.
        "new" => {
            let mut name = uuid_name();
            let mut cpus: u32 = 2;
            let mut memory_mb: u32 = 1024;
            let mut i = 1;
            while i < parts.len() {
                match parts[i] {
                    "--name" | "-n" => {
                        i += 1;
                        if i < parts.len() { name = parts[i].to_string(); }
                    }
                    "--cpus" | "-c" => {
                        i += 1;
                        if i < parts.len() { cpus = parts[i].parse().unwrap_or(2); }
                    }
                    "--memory" | "--mem" | "-m" => {
                        i += 1;
                        if i < parts.len() { memory_mb = parts[i].parse().unwrap_or(1024); }
                    }
                    arg if !arg.starts_with('-') => { name = parts[i].to_string(); }
                    _ => {}
                }
                i += 1;
            }
            let vm = api.create_vm(&name, cpus, memory_mb, &user.id).await?;
            Ok(format!(
                "✓ VM '{}' created\r\n  IP: {}\r\n  CPUs: {}  Memory: {} MiB\r\n  SSH: ssh root@{}\r\n",
                vm.name, vm.ip, vm.cpus, vm.memory_mb, vm.ip
            ))
        }

        // ── rm / destroy ───────────────────────────────────────────────────
        "rm" | "destroy" => {
            if parts.len() < 2 {
                return Ok("usage: rm <name>\r\n".to_string());
            }
            let name = parts[1];
            check_owns(api, name, user).await?;
            api.destroy_vm(name).await?;
            Ok(format!("✓ VM '{}' destroyed\r\n", name))
        }

        // ── stop ───────────────────────────────────────────────────────────
        "stop" => {
            if parts.len() < 2 {
                return Ok("usage: stop <name>\r\n".to_string());
            }
            check_owns(api, parts[1], user).await?;
            let vm = api.stop_vm(parts[1]).await?;
            Ok(format!("✓ VM '{}' stopped\r\n", vm.name))
        }

        // ── restart ────────────────────────────────────────────────────────
        "restart" => {
            if parts.len() < 2 {
                return Ok("usage: restart <name>\r\n".to_string());
            }
            check_owns(api, parts[1], user).await?;
            let vm = api.restart_vm(parts[1]).await?;
            Ok(format!("✓ VM '{}' restarted (status: {})\r\n", vm.name, vm.status))
        }

        // ── rename ─────────────────────────────────────────────────────────
        "rename" => {
            if parts.len() < 3 {
                return Ok("usage: rename <old-name> <new-name>\r\n".to_string());
            }
            check_owns(api, parts[1], user).await?;
            api.rename_vm(parts[1], parts[2]).await?;
            Ok(format!("✓ VM '{}' renamed to '{}'\r\n", parts[1], parts[2]))
        }

        // ── cp / copy ──────────────────────────────────────────────────────
        // The copy is owned by the same user as the source.
        "cp" | "copy" => {
            if parts.len() < 2 {
                return Ok("usage: cp <source> [new-name]\r\n".to_string());
            }
            let source = parts[1];
            let new_name = if parts.len() >= 3 {
                parts[2].to_string()
            } else {
                let prefix = &source[..source.len().min(6)];
                format!("{}-copy", prefix)
            };
            check_owns(api, source, user).await?;
            let vm = api.copy_vm(source, &new_name, &user.id).await?;
            Ok(format!(
                "✓ VM '{}' copied to '{}'\r\n  IP: {}\r\n  SSH: ssh root@{}\r\n",
                source, vm.name, vm.ip, vm.ip
            ))
        }

        // ── whoami ─────────────────────────────────────────────────────────
        "whoami" => {
            Ok(format!(
                "email:      {}\r\nuser-id:    {}\r\ncreated:    {}\r\n",
                user.email, user.id, user.created_at,
            ))
        }

        // ── ssh-key ────────────────────────────────────────────────────────
        "ssh-key" => {
            if parts.len() < 2 {
                return Ok("usage: ssh-key <list|remove>\r\n".to_string());
            }
            match parts[1] {
                "list" => {
                    let conn = crate::db::open(db_path)?;
                    let keys = crate::db::list_ssh_keys(&conn, &user.id)?;
                    if keys.is_empty() {
                        return Ok("no keys\r\n".to_string());
                    }
                    let mut out = String::new();
                    for k in &keys {
                        out.push_str(&format!("{:16}  {}\r\n", k.name, &k.fingerprint[..16]));
                    }
                    Ok(out)
                }
                "remove" => {
                    if parts.len() < 3 {
                        return Ok("usage: ssh-key remove <fingerprint-prefix>\r\n".to_string());
                    }
                    let fp_prefix = parts[2];
                    let conn = crate::db::open(db_path)?;
                    let keys = crate::db::list_ssh_keys(&conn, &user.id)?;
                    let matching: Vec<_> = keys
                        .iter()
                        .filter(|k| k.fingerprint.starts_with(fp_prefix))
                        .collect();
                    match matching.len() {
                        0 => Ok(format!("no key matching '{}'\r\n", fp_prefix)),
                        1 => {
                            if crate::db::remove_ssh_key(&conn, &user.id, &matching[0].fingerprint)? {
                                Ok(format!("✓ key '{}' removed\r\n", matching[0].name))
                            } else {
                                Ok("key not found\r\n".to_string())
                            }
                        }
                        n => Ok(format!(
                            "{} keys match prefix '{}'; be more specific\r\n",
                            n, fp_prefix
                        )),
                    }
                }
                _ => Ok("usage: ssh-key <list|remove>\r\n".to_string()),
            }
        }

        // ── expose ─────────────────────────────────────────────────────────
        "expose" => {
            if parts.len() < 2 {
                return Ok("usage: expose <vm> [--port <n>]\r\n".to_string());
            }
            let vm_name = parts[1];
            let port: u16 = parts.windows(2)
                .find(|w| w[0] == "--port" || w[0] == "-p")
                .and_then(|w| w[1].parse().ok())
                .unwrap_or(80);
            check_owns(api, vm_name, user).await?;
            api.expose_vm(vm_name, port).await?;
            Ok(format!(
                "✓ VM '{}' exposed on proxy port {}\r\n  URL: https://{}.miniclankers.com\r\n",
                vm_name, port, vm_name
            ))
        }

        // ── set-public / set-private ────────────────────────────────────────
        "set-public" => {
            if parts.len() < 2 {
                return Ok("usage: set-public <vm>\r\n".to_string());
            }
            check_owns(api, parts[1], user).await?;
            api.set_vm_public(parts[1]).await?;
            Ok(format!(
                "✓ VM '{}' is now publicly accessible (no login required)\r\n",
                parts[1]
            ))
        }
        "set-private" => {
            if parts.len() < 2 {
                return Ok("usage: set-private <vm>\r\n".to_string());
            }
            check_owns(api, parts[1], user).await?;
            api.set_vm_private(parts[1]).await?;
            Ok(format!(
                "✓ VM '{}' is now private (login required to access)\r\n",
                parts[1]
            ))
        }

        // ── help ───────────────────────────────────────────────────────────
        "help" | "--help" | "-h" => Ok(help()),

        // ── unknown ────────────────────────────────────────────────────────
        unknown => Ok(format!(
            "unknown command '{}'. Type 'help' for available commands.\r\n",
            unknown
        )),
    }
}

fn help() -> String {
    [
        "MINICLANKERS.COM — VM management",
        "",
        "  ls                              list your VMs",
        "  new [name] [--cpus N] [--mem M] create a new VM",
        "  rm <name>                       destroy a VM",
        "  stop <name>                     stop a VM (keep rootfs)",
        "  restart <name>                  reboot a running VM",
        "  rename <old> <new>              rename a stopped VM",
        "  cp <source> [new-name]          copy a VM",
        "",
        "  expose <vm> [--port N]          expose VM web server on port N (default 80)",
        "  set-public <vm>                 make VM web accessible without login",
        "  set-private <vm>                require login to access VM web (default)",
        "",
        "  whoami                          show your account info",
        "  ssh-key list                    list your registered SSH keys",
        "  ssh-key remove <prefix>         remove an SSH key",
        "",
        "  help                            show this help",
        "",
        "  SSH into a VM:  ssh -p 2222 <vmname>@ssh.miniclankers.com",
        "  Web access:     https://<vmname>.miniclankers.com",
        "",
    ]
    .join("\r\n")
}

/// Generate a short random VM name (6 hex chars).
fn uuid_name() -> String {
    let id = uuid::Uuid::new_v4().to_string();
    id[..6].to_string()
}
