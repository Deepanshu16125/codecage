//! CodeCage: run untrusted WASI plugins inside a locked-down sandbox.
use anyhow::{anyhow, bail, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use wasmtime::{Config, Engine, Linker, Module, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
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
}

const USAGE: &str = "usage: codecage run <plugin.wasm> [options]

options:
  --fuel N            CPU budget (default 50000000)
  --memory-mb N       memory cap in MiB (default 64)
  --timeout-ms N      wall-clock timeout (default 2000)
  --no-fuel           skip fuel; timeout still applies
  --max-output-kb N   cap on stdout/stderr each (default 1024)
  --allow-dir PATH    grant read-only access (guest path /data, or /data0 /data1 …)
  --allow-write-dir PATH  grant read-write access (same guest naming)

by default a plugin gets no files, no network, and no environment variables.";

fn parse_args() -> Result<RunOpts> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("run") || args.len() < 2 {
        bail!("{USAGE}");
    }
    let mut o = RunOpts {
        plugin: args[1].clone(),
        fuel: 50_000_000,
        memory_mb: 64,
        timeout_ms: 2000,
        no_fuel: false,
        max_output_kb: 1024,
        dirs: Vec::new(),
    };
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--no-fuel" {
            o.no_fuel = true;
            i += 1;
            continue;
        }
        let val = args.get(i + 1).ok_or_else(|| anyhow!("missing value for {}", args[i]))?;
        match args[i].as_str() {
            "--fuel" => o.fuel = val.parse()?,
            "--memory-mb" => o.memory_mb = val.parse()?,
            "--timeout-ms" => o.timeout_ms = val.parse()?,
            "--max-output-kb" => o.max_output_kb = val.parse()?,
            "--allow-dir" => {
                o.dirs.push(AllowDir {
                    host: PathBuf::from(val),
                    guest: String::new(),
                    write: false,
                });
            }
            "--allow-write-dir" => {
                o.dirs.push(AllowDir {
                    host: PathBuf::from(val),
                    guest: String::new(),
                    write: true,
                });
            }
            other => bail!("unknown option {other}\n\n{USAGE}"),
        }
        i += 2;
    }
    // Assign stable guest paths: one dir -> /data, several -> /data0 /data1 …
    let n = o.dirs.len();
    for (idx, d) in o.dirs.iter_mut().enumerate() {
        d.guest = if n == 1 {
            "/data".into()
        } else {
            format!("/data{idx}")
        };
        if !d.host.is_dir() {
            bail!("--allow-dir path is not a directory: {}", d.host.display());
        }
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

fn build_wasi(dirs: &[AllowDir], out: &MemoryOutputPipe, err: &MemoryOutputPipe) -> Result<WasiP1Ctx> {
    let mut b = WasiCtxBuilder::new();
    b.stdout(out.clone()).stderr(err.clone());
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
    let o = parse_args()?;

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
    let wasi = build_wasi(&o.dirs, &out_pipe, &err_pipe)?;
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