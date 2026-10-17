fn main() {
    for p in [
        "../Cargo.toml",
        "/data/../Cargo.toml",
        "/data/../../Windows/System32/drivers/etc/hosts",
    ] {
        match std::fs::read_to_string(p) {
            Ok(s) => {
                println!("ESCAPED via {p}: {} bytes", s.len());
                std::process::exit(0);
            }
            Err(e) => eprintln!("blocked {p}: {e}"),
        }
    }
    eprintln!("escape_preopen: all attempts blocked");
    std::process::exit(1);
}
