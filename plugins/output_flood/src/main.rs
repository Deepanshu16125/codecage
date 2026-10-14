use std::io::Write;
fn main() {
    let line = [b'A'; 1023];
    let mut out = std::io::stdout().lock();
    loop {
        if out.write_all(&line).is_err() || out.write_all(b"\n").is_err() {
            std::process::exit(1);
        }
    }
}
