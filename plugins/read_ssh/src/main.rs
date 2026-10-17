fn main() {
    let paths = [
        "/data/../.ssh/id_rsa",
        "/.ssh/id_rsa",
        "C:\\Users\\THEDE\\.ssh\\id_rsa",
        "/data/../../../../../../Users/THEDE/.ssh/id_rsa",
    ];
    for p in paths {
        match std::fs::read_to_string(p) {
            Ok(s) => {
                println!("LEAKED {p}: {} bytes", s.len());
                std::process::exit(0);
            }
            Err(e) => eprintln!("blocked {p}: {e}"),
        }
    }
    eprintln!("read_ssh: all attempts blocked");
    std::process::exit(1);
}
