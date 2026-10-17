fn main() {
    let mut v: Vec<Vec<u8>> = Vec::new();
    loop {
        v.push(vec![1u8; 8 * 1024 * 1024]);
    }
}
