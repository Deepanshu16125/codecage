//! End-to-end sandbox tests: every malicious plugin must be stopped, benign ones must work.
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Once;

const PLUGINS: &[&str] = &[
    "hello", "primes", "linecount", "infinite_loop", "mem_bomb", "read_ssh",
    "escape_preopen", "env_snoop", "try_write", "output_flood", "sleep_forever",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn build_plugins() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let mut cmd = Command::new(env!("CARGO"));
        cmd.current_dir(root())
            .args(["build", "--release", "--target", "wasm32-wasip1"]);
        for p in PLUGINS {
            cmd.args(["-p", p]);
        }
        let st = cmd.status().expect("cargo build plugins");
        assert!(st.success(), "building plugins failed");
    });
}

fn plugin(name: &str) -> String {
    root()
        .join("target/wasm32-wasip1/release")
        .join(format!("{name}.wasm"))
        .to_string_lossy()
        .into_owned()
}

fn cage(name: &str, extra: &[&str]) -> Output {
    build_plugins();
    let p = plugin(name);
    let mut args = vec!["run", p.as_str()];
    args.extend_from_slice(extra);
    Command::new(env!("CARGO_BIN_EXE_codecage"))
        .current_dir(root())
        .env("SECRET_TOKEN", "hunter2")
        .env("CODECAGE_LOG", root().join("target").join("test-audit.log"))
        .args(&args)
        .output()
        .expect("run codecage")
}

fn out(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn assert_denied(o: &Output, reason: &str) {
    let s = out(o);
    assert_eq!(o.status.code(), Some(2), "expected DENIED exit 2, got {:?}\n{s}", o.status.code());
    assert!(s.contains("DENIED") && s.contains(reason), "expected DENIED containing {reason:?}\n{s}");
}

/// Plugin tried something and was refused (it exits 1 and never prints a leak marker).
fn assert_blocked(o: &Output) {
    let s = out(o);
    assert_eq!(o.status.code(), Some(1), "expected plugin to fail with 1\n{s}");
    for marker in ["LEAKED", "ESCAPED", "WROTE"] {
        assert!(!s.contains(marker), "sandbox leaked ({marker})\n{s}");
    }
}

#[test]
fn hello_runs() {
    let o = cage("hello", &[]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("hello from the cage"));
}

#[test]
fn primes_correct() {
    let o = cage("primes", &["--fuel", "10000000000"]);
    assert!(out(&o).contains("primes below 2000000: 148933"), "{}", out(&o));
}

#[test]
fn linecount_needs_permission() {
    assert_blocked(&cage("linecount", &[]));
    let o = cage("linecount", &["--allow-dir", "demo_data"]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("3 lines"), "{}", out(&o));
}

#[test]
fn infinite_loop_hits_fuel() {
    assert_denied(&cage("infinite_loop", &[]), "fuel");
}

#[test]
fn infinite_loop_hits_timeout_without_fuel() {
    assert_denied(&cage("infinite_loop", &["--no-fuel", "--timeout-ms", "300"]), "timeout");
}

#[test]
fn mem_bomb_hits_memory_cap() {
    assert_denied(&cage("mem_bomb", &["--no-fuel", "--timeout-ms", "5000"]), "memory");
}

#[test]
fn read_ssh_blocked() {
    assert_blocked(&cage("read_ssh", &["--allow-dir", "demo_data"]));
}

#[test]
fn escape_preopen_blocked() {
    assert_blocked(&cage("escape_preopen", &["--allow-dir", "demo_data"]));
}

#[test]
fn env_is_empty() {
    assert_blocked(&cage("env_snoop", &[]));
}

#[test]
fn read_only_dir_rejects_writes() {
    assert_blocked(&cage("try_write", &["--allow-dir", "demo_data"]));
    assert!(!root().join("demo_data/evil.txt").exists());
}

#[test]
fn output_flood_capped() {
    assert_denied(&cage("output_flood", &["--max-output-kb", "64"]), "output");
}

#[test]
fn sleep_forever_times_out() {
    assert_denied(&cage("sleep_forever", &["--timeout-ms", "500"]), "timeout");
}
#[test]
fn audit_records_denials() {
    let log = std::env::temp_dir().join(format!("codecage-audit-test-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&log);
    build_plugins();
    let bin = env!("CARGO_BIN_EXE_codecage");
    for (p, extra) in [("hello", vec![]), ("infinite_loop", vec![]), ("mem_bomb", vec!["--no-fuel"])] {
        let pp = plugin(p);
        let mut a = vec!["run", pp.as_str()];
        a.extend(extra);
        Command::new(bin).env("CODECAGE_LOG", &log).args(&a).output().unwrap();
    }
    let o = Command::new(bin).env("CODECAGE_LOG", &log).arg("audit").output().unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{s}");
    assert!(s.contains("hello") && s.contains("infinite_loop") && s.contains("mem_bomb"), "{s}");
    assert!(s.contains("cpu (fuel)") && s.contains("memory"), "{s}");
    assert!(s.contains("TOTAL                  3     1       2"), "{s}");
    let _ = std::fs::remove_file(&log);
}