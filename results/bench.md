Machine: 12th Gen Intel(R) Core(TM) i7-12700H, 20 runs each (plus one warm-up). Times are whole-process wall-clock ms; exec ms is the plugin's own run time reported by codecage.

| Benchmark | What it measures | Median ms | Min ms | p95 ms | Exec ms (median) |
|---|---|---|---|---|---|
| hello_cold | hello, compile cache cleared before every run | 29.1 | 25.8 | 39.5 | 0 |
| hello_warm | hello, compiled module loaded from cache | 9.3 | 8.6 | 12.2 | 0 |
| primes_fuel | primes to 2M in the cage, fuel metering on | 17.6 | 16.5 | 20.8 | 8 |
| primes_nofuel | primes to 2M in the cage, --no-fuel | 16.6 | 15 | 21.7 | 7 |
| primes_native | same primes source built as a native program | 12.4 | 11.7 | 23 |  |

- Compile cache makes startup **3.1 x** faster (cold vs warm median).
- Caged primes (with fuel) takes **1.42 x** the wall time of the native program.
- Fuel metering costs **6 %** wall time on primes versus --no-fuel.
