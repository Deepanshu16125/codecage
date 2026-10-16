//! CodeCage: run untrusted WASI plugins inside a locked-down sandbox.
use anyhow::{anyhow, bail, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use wasmtime::{Config, Engine, Linker, Module, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
mod policy;

use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::{FsPerms, WasiCtxBuilder};

struct State {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
    memory_denied: bool,
}

impl ResourceLimiter for State {
    fn memory_growing(&mut self, cur: usize, desired: usize, max: Option<usize>) -> wasmtime::Result<bool> {
        let ok = self.limits.memory_growing(cur, desired, max)?;
        if !ok {
            self.memory_denied = true;
        }
        Ok(ok)
    }
    fn table_growing(&mut self, cur: usize, desired: usize, max: Option<usize>) -> wasmtime::Result<bool> {
        self.limits.table_growing(cur, desired, max)
    }
}

struct AllowDir {
    host: PathBuf,
    guest: String,
    write: bool,
}

struct RunOpts {
    plugin: String,
    fuel: u64,
    memory_mb: usize,
    timeout_ms: u64,
    no_fuel: bool,
    max_output_kb: usize,
    dirs: Vec<AllowDir>,
    env: Vec<(String, String)>,
}

const USAGE: &str = "usage: codecage run <plugin.wasm> [options]
       codecage audit [--plugin NAME] [--clear]

options:
  --policy FILE       load limits and grants from a codecage.toml policy file
  --fuel N            CPU budget (default 50000000)
  --memory-mb N       memory cap in MiB (default 64)
  --timeout-ms N      wall-clock timeout (default 2000)
  --no-fuel           skip fuel; timeout still applies
  --max-output-kb N   cap on stdout/stderr each (default 1024)
  --allow-dir PATH    grant read-only access (guest path /data, or /data0 /data1 ...)
  --allow-write-dir PATH  grant read-write access (same guest naming)
  --allow-env NAME    pass one host environment variable through

precedence: command-line flags > policy file > defaults.
by default a plugin gets no files, no network, and no environment variables.";

fn parse_args() -> Result<RunOpts> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("run") || args.len() < 2 {
        bail!("{USAGE}");
    }
    let plugin = args[1].clone();
    let mut cli = policy::Limits::default();
    let mut cli_read: Vec<PathBuf> = Vec::new();
    let mut cli_write: Vec<PathBuf> = Vec::new();
    let mut cli_env: Vec<String> = Vec::new();
    let mut policy_path: Option<PathBuf> = None;
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--no-fuel" {
            cli.no_fuel = Some(true);
            i += 1;
            continue;
        }
        let val = args.get(i + 1).ok_or_else(|| anyhow!("missing value for {}", args[i]))?;
        match args[i].as_str() {
            "--policy" => policy_path = Some(PathBuf::from(val)),
            "--fuel" => cli.fuel = Some(val.parse()?),
            "--memory-mb" => cli.memory_mb = Some(val.parse()?),
            "--timeout-ms" => cli.timeout_ms = Some(val.parse()?),
            "--max-output-kb" => cli.max_output_kb = Some(val.parse()?),
            "--allow-dir" => cli_read.push(PathBuf::from(val)),
            "--allow-write-dir" => cli_write.push(PathBuf::from(val)),
            "--allow-env" => cli_env.push(val.clone()),
            other => bail!("unknown option {other}\n\n{USAGE}"),
        }
        i += 2;
    }

    let pol = match &policy_path {
        Some(p) => {
            let pol = policy::load(p)?;
            eprintln!("[codecage] policy {}", p.display());
            for w in policy::warnings(&pol) {
                eprintln!("[codecage] WARNING: policy {w}");
            }
            pol
        }
        None => policy::Policy::default(),
    };

    let mut o = RunOpts {
        plugin,
        fuel: cli.fuel.or(pol.limits.fuel).unwrap_or(50_000_000),
        memory_mb: cli.memory_mb.or(pol.limits.memory_mb).unwrap_or(64),
        timeout_ms: cli.timeout_ms.or(pol.limits.timeout_ms).unwrap_or(2000),
        no_fuel: cli.no_fuel.or(pol.limits.no_fuel).unwrap_or(false),
        max_output_kb: cli.max_output_kb.or(pol.limits.max_output_kb).unwrap_or(1024),
        dirs: Vec::new(),
        env: Vec::new(),
    };
    for (paths, write) in [(&pol.fs.read, false), (&pol.fs.write, true), (&cli_read, false), (&cli_write, true)] {
        for p in paths {
            o.dirs.push(AllowDir { host: p.clone(), guest: String::new(), write });
        }
    }
    for name in pol.env.allow.iter().chain(cli_env.iter()) {
        match std::env::var(name) {
            Ok(v) => o.env.push((name.clone(), v)),
            Err(_) => eprintln!("[codecage] note: allowed env var {name} is not set on the host"),
        }
    }

    // Assign stable guest paths: one dir -> /data, several -> /data0 /data1 ...
    let n = o.dirs.len();
    for (idx, d) in o.dirs.iter_mut().enumerate() {
        d.guest = if n == 1 { "/data".into() } else { format!("/data{idx}") };
        if !d.host.is_dir() {
            bail!("allowed path is not a directory: {}", d.host.display());
        }
    }
    Ok(o)
}
static PLUGIN: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Where run/deny events are appended. Override with CODECAGE_LOG.
fn log_path() -> PathBuf {
    if let Some(p) = std::env::var_os("CODECAGE_LOG") {
        return PathBuf::from(p);
    }
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("codecage")
        .join("audit.log")
}

/// Append one tab-separated event: unix_secs, plugin, outcome, detail.
fn log_event(outcome: &str, detail: &str) {
    use std::io::Write;
    let path = log_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let plugin = PLUGIN.get().map(String::as_str).unwrap_or("?");
    let clean = detail.replace(['\t', '\n', '\r'], " ");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{ts}\t{plugin}\t{outcome}\t{clean}");
    }
}

fn deny(reason: &str) -> ! {
    log_event("DENIED", reason);
    eprintln!("[codecage] DENIED: {reason}");
    std::process::exit(2);
}

/// Short category for a denial reason, used by `codecage audit`.
fn category(reason: &str) -> &'static str {
    if reason.contains("fuel") {
        "cpu (fuel)"
    } else if reason.contains("timeout") {
        "timeout"
    } else if reason.contains("memory") {
        "memory"
    } else if reason.contains("output") {
        "output"
    } else {
        "trap/other"
    }
}

fn run_audit(args: &[String]) -> Result<()> {
    let path = log_path();
    if args.iter().any(|a| a == "--clear") {
        let _ = std::fs::remove_file(&path);
        println!("audit log cleared ({})", path.display());
        return Ok(());
    }
    let filter = args
        .iter()
        .position(|a| a == "--plugin")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut per: std::collections::BTreeMap<String, [usize; 3]> = Default::default();
    let mut cats: std::collections::BTreeMap<&'static str, usize> = Default::default();
    let mut recent: Vec<(u64, String, String)> = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        if parts.len() < 4 {
            continue;
        }
        let (ts, plugin, outcome, detail) = (parts[0], parts[1], parts[2], parts[3]);
        if let Some(f) = &filter {
            if plugin != f {
                continue;
            }
        }
        let e = per.entry(plugin.to_string()).or_default();
        match outcome {
            "OK" => e[0] += 1,
            "DENIED" => {
                e[1] += 1;
                *cats.entry(category(detail)).or_default() += 1;
                recent.push((ts.parse().unwrap_or(0), plugin.to_string(), detail.to_string()));
            }
            _ => e[2] += 1,
        }
    }
    println!("CodeCage audit  ({})\n", path.display());
    if per.is_empty() {
        println!("no runs recorded yet");
        return Ok(());
    }
    println!("{:<18} {:>5} {:>5} {:>7} {:>9}", "plugin", "runs", "ok", "denied", "exit!=0");
    let mut tot = [0usize; 3];
    for (p, c) in &per {
        println!("{:<18} {:>5} {:>5} {:>7} {:>9}", p, c[0] + c[1] + c[2], c[0], c[1], c[2]);
        for i in 0..3 {
            tot[i] += c[i];
        }
    }
    println!("{:<18} {:>5} {:>5} {:>7} {:>9}", "TOTAL", tot[0] + tot[1] + tot[2], tot[0], tot[1], tot[2]);
    if !cats.is_empty() {
        println!("\ndenials by limit:");
        for (k, v) in &cats {
            println!("  {k:<12} {v}");
        }
        println!("\nlast denials:");
        for (ts, p, d) in recent.iter().rev().take(10) {
            println!("  [{ts}] {p}: {d}");
        }
    }
    Ok(())
}
/// Load a plugin, reusing a cached native compilation when the bytes haven't changed.
fn load_module(engine: &Engine, path: &str) -> Result<Module> {
    use std::hash::{Hash, Hasher};
    let bytes = std::fs::read(path).map_err(|e| anyhow!("could not load {path}: {e}"))?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    engine.precompile_compatibility_hash().hash(&mut h);
    let base = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("codecage").join("cache");
    let cached = dir.join(format!("{:016x}.cwasm", h.finish()));
    if cached.exists() {
        // SAFETY: the cache file was written by this program for this exact engine config.
        if let Ok(m) = unsafe { Module::deserialize_file(engine, &cached) } {
            return Ok(m);
        }
    }
    let module = Module::new(engine, &bytes).map_err(|e| anyhow!("could not load {path}: {e}"))?;
    if std::fs::create_dir_all(&dir).is_ok() {
        if let Ok(ser) = module.serialize() {
            let _ = std::fs::write(&cached, ser);
        }
    }
    Ok(module)
}

fn build_wasi(dirs: &[AllowDir], env: &[(String, String)], out: &MemoryOutputPipe, err: &MemoryOutputPipe) -> Result<WasiP1Ctx> {
    let mut b = WasiCtxBuilder::new();
    b.stdout(out.clone()).stderr(err.clone());
    for (k, v) in env {
        b.env(k, v);
        eprintln!("[codecage] allowed env {k}");
    }
    for d in dirs {
        let perms = if d.write {
            FsPerms::ReadWrite
        } else {
            FsPerms::ReadOnly
        };
        b.preopened_dir(Path::new(&d.host), &d.guest, perms)
            .map_err(|e| anyhow!("preopen {}: {e}", d.host.display()))?;
        eprintln!(
            "[codecage] allowed {} -> {} ({})",
            d.host.display(),
            d.guest,
            if d.write { "read-write" } else { "read-only" }
        );
    }
    Ok(b.build_p1())
}

fn main() -> Result<()> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.first().map(String::as_str) == Some("audit") {
        return run_audit(&raw[1..]);
    }
    let o = parse_args()?;
    let name = Path::new(&o.plugin)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| o.plugin.clone());
    let _ = PLUGIN.set(name);

    let mut config = Config::new();
    config.consume_fuel(!o.no_fuel);
    config.epoch_interruption(true);
    let engine = Engine::new(&config).map_err(anyhow::Error::from)?;
    let module = load_module(&engine, &o.plugin)?;

    let mut linker: Linker<State> = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |s: &mut State| &mut s.wasi).map_err(anyhow::Error::from)?;

    let cap = o.max_output_kb * 1024;
    let out_pipe = MemoryOutputPipe::new(cap);
    let err_pipe = MemoryOutputPipe::new(cap);
    let wasi = build_wasi(&o.dirs, &o.env, &out_pipe, &err_pipe)?;
    let limits = StoreLimitsBuilder::new()
        .memory_size(o.memory_mb * 1024 * 1024)
        .instances(1)
        .build();
    let mut store = Store::new(
        &engine,
        State {
            wasi,
            limits,
            memory_denied: false,
        },
    );
    store.limiter(|s| s);
    if !o.no_fuel {
        store.set_fuel(o.fuel).map_err(anyhow::Error::from)?;
    }
    store.set_epoch_deadline(1);

    let eng = engine.clone();
    let timeout = Duration::from_millis(o.timeout_ms);
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        eng.increment_epoch();
        // A plugin blocked inside a host call (e.g. sleep) can't see the epoch; give it a grace period, then hard-stop.
        std::thread::sleep(Duration::from_millis(250));
        deny(&format!("timeout after {} ms (plugin was blocked in a host call)", timeout.as_millis()));
    });

    let started = Instant::now();
    let result = linker
        .instantiate(&mut store, &module)
        .and_then(|inst| inst.get_typed_func::<(), ()>(&mut store, "_start"))
        .and_then(|start| start.call(&mut store, ()));
    let elapsed = started.elapsed();
    {
        use std::io::Write;
        let o_bytes = out_pipe.contents();
        let e_bytes = err_pipe.contents();
        let _ = std::io::stdout().write_all(&o_bytes);
        let _ = std::io::stderr().write_all(&e_bytes);
        if o_bytes.len() >= cap || e_bytes.len() >= cap {
            deny(&format!("output limit of {} KiB exceeded", o.max_output_kb));
        }
    }
    let used = if o.no_fuel {
        None
    } else {
        Some(o.fuel - store.get_fuel().unwrap_or(0))
    };

    if let Err(e) = result {
        if let Some(exit) = e.downcast_ref::<wasmtime_wasi::I32Exit>() {
            if exit.0 != 0 {
                log_event("EXIT", &format!("code {}", exit.0));
                eprintln!("[codecage] plugin exited with code {}", exit.0);
                std::process::exit(exit.0);
            }
        } else {
            let msg = format!("{e:?}");
            if store.data().memory_denied {
                deny(&format!("memory limit of {} MiB exceeded", o.memory_mb));
            } else if msg.contains("fuel") {
                deny(&format!("CPU budget exhausted (fuel limit {})", o.fuel));
            } else if msg.contains("interrupt") || msg.contains("epoch") {
                deny(&format!("timeout after {} ms", o.timeout_ms));
            } else {
                deny(&format!("plugin trapped: {e}"));
            }
        }
    }
    log_event(
        "OK",
        &format!(
            "fuel {}, {} ms",
            used.map(|u| u.to_string()).unwrap_or_else(|| "off".into()),
            elapsed.as_millis()
        ),
    );
    match used {
        Some(u) => eprintln!(
            "[codecage] ok: fuel used {u}, time {} ms",
            elapsed.as_millis()
        ),
        None => eprintln!(
            "[codecage] ok: fuel off (timeout-only), time {} ms",
            elapsed.as_millis()
        ),
    }
    Ok(())
}