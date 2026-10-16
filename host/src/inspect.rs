//! `codecage inspect`: a static check that lists what a plugin asks the host for, before it ever runs.
use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use wasmtime::Engine;

fn group(name: &str) -> &'static str {
    if name.starts_with("path_") || name == "fd_readdir" || name.starts_with("fd_prestat") {
        "files and folders"
    } else if name.starts_with("environ_") {
        "environment variables"
    } else if name.starts_with("sock_") {
        "network sockets"
    } else if name.starts_with("clock_") || name == "poll_oneoff" {
        "clocks and sleeping"
    } else if name == "random_get" {
        "randomness"
    } else if name == "proc_exit" || name == "proc_raise" || name.starts_with("args_") || name == "sched_yield" {
        "process (exit, args)"
    } else {
        "open handles (read/write/close)"
    }
}

pub fn run(args: &[String]) -> Result<()> {
    let path = args.first().ok_or_else(|| anyhow!("usage: codecage inspect <plugin.wasm>"))?;
    let engine = Engine::default();
    let module = crate::load_module(&engine, path)?;
    let mut groups: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut foreign = Vec::new();
    for imp in module.imports() {
        if imp.module() == "wasi_snapshot_preview1" {
            groups.entry(group(imp.name())).or_default().push(imp.name().to_string());
        } else {
            foreign.push(format!("{}::{}", imp.module(), imp.name()));
        }
    }
    println!("CodeCage inspect  {path}");
    println!("sha256 {}\n", crate::sha256_hex(&std::fs::read(path)?));
    println!("asks the host for:");
    for (g, names) in &groups {
        println!("  {g:<34} {}", names.join(", "));
    }
    if !foreign.is_empty() {
        println!("  {:<34} {}", "NON-WASI imports (will not link)", foreign.join(", "));
    }
    let wants_fs = groups.contains_key("files and folders");
    let wants_env = groups.contains_key("environment variables");
    let wants_net = groups.contains_key("network sockets");
    println!("\nverdict:");
    println!("  files: {}", if wants_fs { "may try to open paths; it only sees folders its policy grants" } else { "never opens paths" });
    println!("  env:   {}", if wants_env { "may read env vars; it only sees names in [env] allow" } else { "never reads env vars" });
    println!("  net:   {}", if wants_net { "uses socket calls; CodeCage grants no sockets" } else { "no network calls" });
    Ok(())
}