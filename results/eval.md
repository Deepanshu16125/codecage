| # | Plugin | Scenario | Threat | Expected | Actual | Reason | Wall ms | Verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | hello | policy | none (benign) | OK | OK |  | 20 | PASS |
| 2 | primes | policy | none (benign, CPU heavy) | OK | OK |  | 19 | PASS |
| 3 | linecount | policy grants demo_data | none (benign, file read) | OK | OK |  | 12 | PASS |
| 4 | linecount | no grant | reads a file it was not given | BLOCKED | BLOCKED | linecount failed: No such file or directory (os error 44) | 11 | PASS |
| 5 | infinite_loop | policy | CPU exhaustion | DENIED:cpu | DENIED:cpu | CPU budget exhausted (fuel limit 50000000) | 14 | PASS |
| 6 | infinite_loop | --no-fuel | CPU exhaustion, fuel off | DENIED:timeout | DENIED:timeout | timeout after 2000 ms | 2010 | PASS |
| 7 | mem_bomb | policy | memory exhaustion | DENIED:memory | DENIED:memory | memory limit of 64 MiB exceeded | 23 | PASS |
| 8 | read_ssh | policy | read SSH keys / system files | BLOCKED | BLOCKED | blocked /data/../.ssh/id_rsa: No such file or directory (os error 44) | 11 | PASS |
| 9 | escape_preopen | policy | path traversal (../) | BLOCKED | BLOCKED | blocked ../Cargo.toml: No such file or directory (os error 44) | 11 | PASS |
| 10 | env_snoop | policy | steal env vars / tokens | BLOCKED | BLOCKED | env_snoop: no environment visible (good) | 13 | PASS |
| 11 | try_write | policy (read-only dir) | write to read-only folder | BLOCKED | BLOCKED | write blocked: Operation not permitted (os error 63) | 15 | PASS |
| 12 | output_flood | policy | stdout flood | DENIED:output | DENIED:output | output limit of 64 KiB exceeded | 11 | PASS |
| 13 | sleep_forever | policy | hang in a host call | DENIED:timeout | DENIED:timeout | timeout after 500 ms (plugin was blocked in a host call) | 767 | PASS |
| 14 | sleep_forever | defaults | hang in a host call | DENIED:timeout | DENIED:timeout | timeout after 2000 ms (plugin was blocked in a host call) | 2262 | PASS |

**14 / 14 scenarios behaved as expected.**
