//! CodeCage: run untrusted WASI plugins inside a locked-down sandbox.
use anyhow::{anyhow, bail, Result};
use std::time::{Duration, Instant};
use wasmtime::{Config, Engine, Linker, Module, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;

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

struct RunOpts {
    plugin: String,
    fuel: u64,
    memory_mb: usize,
    timeout_ms: u64,
}

const USAGE: &str = "usage: codecage run <plugin.wasm> [--fuel N] [--memory-mb N] [--timeout-ms N]

defaults: --fuel 50000000  --memory-mb 64  --timeout-ms 2000
by default a plugin gets no files, no network, and no environment variables.";

fn parse_args() -> Result<RunOpts> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("run") || args.len() < 2 {
        bail!("{USAGE}");
    }
    let mut o = RunOpts { plugin: args[1].clone(), fuel: 50_000_000, memory_mb: 64, timeout_ms: 2000 };
    let mut i = 2;
    while i < args.len() {
        let val = args.get(i + 1).ok_or_else(|| anyhow!("missing value for {}", args[i]))?;
        match args[i].as_str() {
            "--fuel" => o.fuel = val.parse()?,
            "--memory-mb" => o.memory_mb = val.parse()?,
            "--timeout-ms" => o.timeout_ms = val.parse()?,
            other => bail!("unknown option {other}\n\n{USAGE}"),
        }
        i += 2;
    }
    Ok(o)
}

fn deny(reason: &str) -> ! {
    eprintln!("[codecage] DENIED: {reason}");
    std::process::exit(2);
}

/// Load a plugin, reusing a cached native compilation when the bytes haven't changed.
fn load_module(engine: &Engine, path: &str) -> Result<Module> {
    use std::hash::{Hash, Hasher};
    let bytes = std::fs::read(path).map_err(|e| anyhow!("could not load {path}: {e}"))?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    engine.precompile_compatibility_hash().hash(&mut h);
    let base = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
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

fn main() -> Result<()> {    let o = parse_args()?;

    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    let engine = Engine::new(&config).map_err(anyhow::Error::from)?;
    let module = load_module(&engine, &o.plugin)?;

    let mut linker: Linker<State> = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |s: &mut State| &mut s.wasi).map_err(anyhow::Error::from)?;

    // Deny by default: only stdout/stderr, no preopened dirs, no env, no network.
    let wasi = WasiCtxBuilder::new().inherit_stdout().inherit_stderr().build_p1();
    let limits = StoreLimitsBuilder::new()
        .memory_size(o.memory_mb * 1024 * 1024)
        .instances(1)
        .build();
    let mut store = Store::new(&engine, State { wasi, limits, memory_denied: false });
    store.limiter(|s| s);
    store.set_fuel(o.fuel).map_err(anyhow::Error::from)?;
    store.set_epoch_deadline(1);

    // Watchdog: bump the epoch once the wall-clock timeout passes.
    let eng = engine.clone();
    let timeout = Duration::from_millis(o.timeout_ms);
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        eng.increment_epoch();
    });

    let started = Instant::now();
    let result = linker
        .instantiate(&mut store, &module)
        .and_then(|inst| inst.get_typed_func::<(), ()>(&mut store, "_start"))
        .and_then(|start| start.call(&mut store, ()));
    let elapsed = started.elapsed();
    let used = o.fuel - store.get_fuel().unwrap_or(0);

    if let Err(e) = result {
        if let Some(exit) = e.downcast_ref::<wasmtime_wasi::I32Exit>() {
            if exit.0 != 0 {
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
    eprintln!("[codecage] ok: fuel used {used}, time {} ms", elapsed.as_millis());
    Ok(())
}