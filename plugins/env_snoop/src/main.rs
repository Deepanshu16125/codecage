fn main() {
    let keys: Vec<_> = std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
    if keys.is_empty() {
        eprintln!("env_snoop: no environment visible (good)");
        std::process::exit(1);
    }
    println!("LEAKED {} env vars", keys.len());
    for k in keys.iter().take(5) {
        println!("{k}");
    }
    std::process::exit(0);
}
