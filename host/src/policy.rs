//! Per-plugin policy file (`codecage.toml`). Unknown keys are rejected so typos can't silently widen access.
use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub plugin: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub fs: Fs,
    #[serde(default)]
    pub env: Env,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub fuel: Option<u64>,
    pub memory_mb: Option<usize>,
    pub timeout_ms: Option<u64>,
    pub max_output_kb: Option<usize>,
    pub no_fuel: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fs {
    #[serde(default)]
    pub read: Vec<PathBuf>,
    #[serde(default)]
    pub write: Vec<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Env {
    /// Names of host environment variables the plugin may see. Everything else stays hidden.
    #[serde(default)]
    pub allow: Vec<String>,
}

/// Hard ceilings a policy file may not exceed.
pub const MAX_MEMORY_MB: usize = 1024;
pub const MAX_TIMEOUT_MS: u64 = 60_000;

pub fn load(path: &Path) -> Result<Policy> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow!("policy {}: {e}", path.display()))?;
    let mut p: Policy = toml::from_str(&text).map_err(|e| anyhow!("policy {}: {e}", path.display()))?;
    // Folder paths are relative to the policy file, not the current directory.
    let base = path.parent().unwrap_or(Path::new("."));
    for d in p.fs.read.iter_mut().chain(p.fs.write.iter_mut()) {
        if d.is_relative() {
            *d = base.join(&*d);
        }
    }
    if let Some(m) = p.limits.memory_mb {
        if m > MAX_MEMORY_MB {
            return Err(anyhow!("policy {}: memory_mb {m} is above the {MAX_MEMORY_MB} MiB ceiling", path.display()));
        }
    }
    if let Some(t) = p.limits.timeout_ms {
        if t > MAX_TIMEOUT_MS {
            return Err(anyhow!("policy {}: timeout_ms {t} is above the {MAX_TIMEOUT_MS} ms ceiling", path.display()));
        }
    }
    Ok(p)
}

/// Human-readable warnings for policies that grant more than the defaults.
pub fn warnings(p: &Policy) -> Vec<String> {
    let mut w = Vec::new();
    if !p.fs.write.is_empty() {
        w.push(format!("grants WRITE access to {} folder(s)", p.fs.write.len()));
    }
    if !p.env.allow.is_empty() {
        w.push(format!("exposes env vars: {}", p.env.allow.join(", ")));
    }
    if p.limits.no_fuel == Some(true) {
        w.push("disables the fuel (CPU) budget".into());
    }
    if p.limits.memory_mb.is_some_and(|m| m > 256) {
        w.push("memory cap above 256 MiB".into());
    }
    if p.limits.timeout_ms.is_some_and(|t| t > 10_000) {
        w.push("timeout above 10 s".into());
    }
    w
}