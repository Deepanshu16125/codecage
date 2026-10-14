fn main() {
    let n = 2_000_000usize;
    let mut sieve = vec![true; n + 1];
    let mut count = 0;
    for i in 2..=n {
        if sieve[i] {
            count += 1;
            // i * i overflows 32-bit usize on wasm32 once i > 65535, so stop marking past sqrt(n)
            if i > n / i { continue; }
            let mut j = i * i;
            while j <= n { sieve[j] = false; j += i; }
        }
    }
    println!("primes below {n}: {count}");
}
