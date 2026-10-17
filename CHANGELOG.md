# Changelog

All dates are 2026. Tags are on https://github.com/Deepanshu16125/codecage.

## v1.0 - 17 Oct: final project freeze
- `codecage --version` (1.0.0); host crate version bumped to 1.0.0.
- Code formatted with `cargo fmt`, clippy warnings fixed (collapsible `if`s, no behaviour change); duplicate workspace members removed; `.gitignore` extended.
- Fresh results: 26/26 tests, 19/19 evaluation scenarios, dashboard 14/14; hello 28.5 ms cold / 9.4 ms warm, primes caged 1.43x native, fuel metering about 5.5%.

## Live dashboard - 16-17 Oct
- `scripts/dashboard.ps1` + `dashboard.html`: local web page to run any plugin or all of them, change limits and see verdict, output, policy, inspection and audit log (`981f089`).
- Fixed 3/4-column grid, Run button kept inside each card, responsive layout (`3876b74`).
- Non-blocking runs (one process per job), live timers, Stop / Stop all (`CANCELLED`), state survives a page reload, 3 runs at a time, long-timeout warning, custom-limit runs not scored against the policy (`91a3169`).

## v0.5 - 16 Oct: C plugins via Zig
- `c_wordcount`, `c_steal`, `c_spin` written in C and built with `zig cc -target wasm32-wasi` (`scripts/build-c.ps1`); small initial memory so they fit the 16 MiB cap.
- Policies, 3 tests, 3 evaluation scenarios, demo steps; CI installs Zig (`3585c3b`). README (`c889abc`).

## codecage inspect - 16 Oct
- `codecage inspect <plugin.wasm>` lists what a plugin asks the host for (WASI imports grouped by kind) without running it, plus a test (`afaaef0`).

## Demo - 16 Oct
- `scripts/demo.ps1`: one-command narrated, colour-coded demo (13 steps + audit summary) (`588ebec`).

## v0.4.1 - 16 Oct: hash pinning
- Optional `sha256` in the policy; `codecage hash` prints it. A swapped plugin is refused. 2 tests, 2 evaluation scenarios (`09ba2a9`).

## v0.4 - 16 Oct: evaluation, benchmark, report
- `scripts/eval.ps1` (evaluation table, expected vs actual) and `scripts/bench.ps1` (cold/warm startup, caged vs native, fuel on/off) with first results (`bb4f96c`).
- `scripts/report.ps1`: self-contained HTML report `results/report.html` (`68af32d`).

## v0.3 - 16 Oct: policy files
- Per-plugin `codecage.toml` (limits, read/write folders, env allowlist), `--policy` and `--allow-env`; unknown keys rejected, ceilings and warnings; 7 policy tests (`bef2d4f`).

## v0.2 - 14-15 Oct: permissions, guards, tests, audit
- `--allow-dir` / `--allow-write-dir`; `linecount` plus malicious file/env plugins (`329c553`).
- `--no-fuel` timeout-only mode (`48bf906`).
- Output cap, `output_flood` and `sleep_forever` (watchdog hard-stop), automated sandbox tests, GitHub Actions CI on Ubuntu and Windows (`70602d8`).
- Audit log and `codecage audit` (`17a09a1`).

## v0.1 - 14 Oct: first sandbox
- Hello-world WASI plugin and minimal wasmtime host with a fuel limit (`f27f855`, `1312b21`).
- `codecage run` with fuel, memory and timeout limits; `infinite_loop` and `mem_bomb` (`35dec34`).
- Compile cache, optimized release profile, `primes` benchmark plugin (`4765855`).

v0.1 and v0.2 are untagged milestones; v0.3, v0.4, v0.4.1, v0.5 and v1.0 are git tags.
