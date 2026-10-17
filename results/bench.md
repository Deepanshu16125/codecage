Machine: 12th Gen Intel(R) Core(TM) i7-12700H, 20 runs each (plus one warm-up). Times are whole-process wall-clock ms; exec ms is the plugin's own run time reported by codecage.

| Benchmark | What it measures | Median ms | Min ms | p95 ms | Exec ms (median) |
|---|---|---|---|---|---|
| hello_cold | hello, compile cache cleared before every run | 28.5 | 27 | 31.1 | 0 |
| hello_warm | hello, compiled module loaded from cache | 9.4 | 8.6 | 11.4 | 0 |
| primes_fuel | primes to 2M in the cage, fuel metering on | 17.2 | 16.4 | 18.9 | 8 |
| primes_nofuel | primes to 2M in the cage, --no-fuel | 16.3 | 15.2 | 17 | 7 |
| primes_native | same primes source built as a native program | 12 | 11.3 | 12.3 |  |

- Compile cache makes startup **3 x** faster (cold vs warm median).
- Caged primes (with fuel) takes **1.43 x** the wall time of the native program.
- Fuel metering costs **5.5 %** wall time on primes versus --no-fuel.
