# CodeCage

**Run untrusted plugins safely.** CodeCage is a small sandbox host, written in Rust on top of [wasmtime](https://wasmtime.dev/). It runs WebAssembly (WASI) plugins with **no files, no environment variables, no network, and fixed CPU, memory, time and output budgets**. A plugin gets only what its policy file grants.

B.Tech CSE final-year project, Deepanshu (roll no. 233163), SAITM Gurugram (MDU Rohtak). Guide: Dr. Ankita.

## What it stops

| Threat | How CodeCage stops it |
|---|---|
| Infinite loop / CPU burn | wasmtime **fuel** budget, plus an epoch-based wall-clock timeout |
| Hang inside a host call (e.g. `sleep`) | Watchdog hard-stops the process about 250 ms after the timeout |
| Memory bomb | Resource limiter caps linear memory (default 64 MiB) |
| Output flood | stdout/stderr captured in capped buffers (default 1 MiB each) |
| Reading SSH keys / system files | Capability-based WASI: no folder is visible unless granted |
| `../` path traversal | WASI path resolution stays inside the granted folder |
| Writing to a read-only folder | Folders are granted read-only unless the policy says `write` |
| Stealing env vars / tokens | Empty environment; only names listed in `[env] allow` pass through |
| Swapped / tampered plugin | Optional **SHA-256 hash pinning** in the policy |

## Quick start (Windows)

```powershell
rustup target add wasm32-wasip1
cargo build --release -p host                                   # builds codecage.exe
cargo build --release --target wasm32-wasip1 --workspace --exclude host   # builds the plugins

$w = "target\wasm32-wasip1\release"
.\target\release\codecage.exe run $w\hello.wasm
.\target\release\codecage.exe run $w\linecount.wasm --policy plugins\linecount\codecage.toml
.\target\release\codecage.exe run $w\infinite_loop.wasm          # DENIED: CPU budget exhausted
```

## Commands

```
codecage run <plugin.wasm> [options]     run a plugin in the cage
codecage inspect <plugin.wasm>           list what the plugin asks the host for, without running it
codecage hash <plugin.wasm>              print the SHA-256 to pin in a policy
codecage audit [--plugin NAME] [--clear] summarize the audit log (runs, denials by limit)
```

Run options: `--policy FILE`, `--fuel N`, `--memory-mb N`, `--timeout-ms N`, `--no-fuel`, `--max-output-kb N`, `--allow-dir PATH`, `--allow-write-dir PATH`, `--allow-env NAME`.
The order of precedence is command-line flags, then the policy file, then the defaults.

Exit codes: `0` ok, `1`–`255` the plugin's own exit code (for example, a blocked access it reported), `2` with `[codecage] DENIED: ...` a limit stopped it.

## Policy file (`codecage.toml`)

Every plugin ships one, next to its source:

```toml
plugin = "linecount"
description = "Counts lines in /data/sample.txt."
# sha256 = "..."            # optional: only run this exact file (codecage hash plugin.wasm)

[limits]
fuel = 10_000_000           # CPU budget
memory_mb = 16              # linear memory cap (ceiling 1024)
timeout_ms = 1000           # wall clock (ceiling 60000)
max_output_kb = 16          # stdout / stderr cap each
# no_fuel = true            # timeout-only mode

[fs]
read  = ["../../demo_data"] # relative to this file; one folder appears as /data
# write = ["..."]           # read-write grants (prints a WARNING)

[env]
allow = []                  # host env vars the plugin may see
```

Unknown keys are rejected, so a typo can't silently widen access. Grants that go beyond the safe defaults print a `WARNING`: write access, exposed env vars, fuel turned off, memory over 256 MiB, or a timeout over 10 s.

## Plugins

| Plugin | Language | Kind | What it does |
|---|---|---|---|
| hello | Rust | benign | prints a greeting |
| primes | Rust | benign | sieve to 2,000,000 (148,933 primes) |
| linecount | Rust | benign | counts lines in `/data/sample.txt` |
| c_wordcount | C | benign | counts lines and words in `/data/sample.txt` |
| infinite_loop | Rust | malicious | spins forever |
| c_spin | C | malicious | spins forever |
| mem_bomb | Rust | malicious | allocates until stopped |
| output_flood | Rust | malicious | floods stdout |
| sleep_forever | Rust | malicious | blocks in a host sleep call |
| read_ssh | Rust | malicious | tries SSH keys and system files |
| escape_preopen | Rust | malicious | tries `../` traversal |
| env_snoop | Rust | malicious | tries to read env vars |
| try_write | Rust | malicious | writes into a read-only folder |
| c_steal | C | malicious | files, `../`, write and env attacks in one |

The C plugins are built with Zig's clang and wasi-libc: `powershell -File scripts\build-c.ps1` (install Zig with `winget install zig.zig`).

## Evaluation, benchmarks, report and demo

| Script | Output |
|---|---|
| `scripts\eval.ps1` | `results\eval.csv` and `eval.md`: every plugin and scenario, expected vs actual, with a PASS/FAIL verdict |
| `scripts\bench.ps1` | `results\bench.csv` and `bench.md`: cold vs warm startup, caged vs native, fuel on vs off |
| `scripts\report.ps1 [-Fresh]` | `results\report.html`: a one-page report with the tables and charts |
| `scripts\demo.ps1 [-NoPause] [-OpenReport]` | a narrated, colour-coded live demo |
| `scripts\dashboard.ps1` | live web dashboard at http://localhost:8765: run any plugin or all of them, change limits, see output, policy, inspection and the audit log (`?autorun=1` runs everything on load) |

Run all of them with `powershell -ExecutionPolicy Bypass -File <script>`.

Latest results (i7-12700H laptop): **19 / 19** evaluation scenarios behave as expected. The compile cache makes startup **3.1x** faster (29.1 ms cold, 9.3 ms warm). The caged plugin takes **1.42x** native time on primes, and fuel metering costs about **6%** of that.

## Tests and CI

`cargo test -p host --release` runs 26 end-to-end tests: every malicious plugin must be stopped and every benign one must work. GitHub Actions runs them on Ubuntu and Windows on every push.

## Known limitations

- File and env refusals happen inside WASI, so the plugin sees an error (EPERM, ENOENT). The audit log records them as a non-zero exit, not as the exact path. Wrapping wasmtime-wasi's `path_open` from the host traps, so path-level logging is future work.
- `inspect` reports `environ_get` for every Rust plugin, because Rust's standard library always asks for env vars at startup. The plugin still sees only what `[env] allow` lists.
- WASI preview 1 has no sockets to grant, so network is denied by construction. A network allowlist would need WASI preview 2.

## Layout

```
host/            the codecage binary (main.rs, policy.rs, inspect.rs) and tests/sandbox.rs
plugins/         Rust plugins, each with a codecage.toml
plugins_c/       C plugins, each with a codecage.toml
demo_data/       sample.txt, the folder plugins may be granted
scripts/         eval, bench, report, demo, build-c
results/         generated CSV, markdown and HTML
```