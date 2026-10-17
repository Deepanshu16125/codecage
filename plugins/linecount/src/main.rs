fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/data/sample.txt".into());
    match std::fs::read_to_string(&path) {
        Ok(s) => println!("{path}: {} lines", s.lines().count()),
        Err(e) => {
            eprintln!("linecount failed: {e}");
            std::process::exit(1);
        }
    }
}
