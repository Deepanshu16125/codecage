fn main() {
    match std::fs::write("/data/evil.txt", b"pwned") {
        Ok(_) => {
            println!("WROTE");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("write blocked: {e}");
            std::process::exit(1);
        }
    }
}
