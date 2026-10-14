use anyhow::{bail, Context, Result};
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        bail!("usage: host <plugin.wasm> [--fuel N]");
    }
    let path = &args[1];
    let fuel: Option<u64> = args
        .iter()
        .position(|a| a == "--fuel")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.parse())
        .transpose()?;

    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config)?;
    let module = Module::from_file(&engine, path).map_err(anyhow::Error::from).with_context(|| format!("loading {path}"))?;

    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |s| s)?;

    let wasi = WasiCtxBuilder::new().inherit_stdout().inherit_stderr().build_p1();
    let mut store = Store::new(&engine, wasi);
    store.set_fuel(fuel.unwrap_or(u64::MAX))?;

    let instance = linker.instantiate(&mut store, &module)?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    let result = start.call(&mut store, ());
    let used = fuel.map(|f| f - store.get_fuel().unwrap_or(0));

    match result {
        Ok(()) => {}
        Err(e) => {
            if let Some(exit) = e.downcast_ref::<wasmtime_wasi::I32Exit>() {
                if exit.0 != 0 { bail!("plugin exited with code {}", exit.0); }
            } else if let Some(trap) = e.downcast_ref::<wasmtime::Trap>() {
                if *trap == wasmtime::Trap::OutOfFuel {
                    bail!("[codecage] DENIED: plugin ran out of fuel (limit {:?})", fuel);
                }
                bail!("[codecage] plugin trapped: {trap}");
            } else {
                return Err(e.into());
            }
        }
    }
    if let Some(u) = used { eprintln!("[codecage] fuel used: {u}"); }
    Ok(())
}

