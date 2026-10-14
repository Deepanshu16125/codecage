fn main() {
    let n = 2_000_000usize;
    let mut sieve = vec![true; n + 1];
    let mut count = 0;
    for i in 2..=n {
        if sieve[i] {
            count += 1;
            let mut j = i * i;
            while j <= n { sieve[j] = false; j += i; }
        }
    }
    println!("primes below {n}: {count}");
}
