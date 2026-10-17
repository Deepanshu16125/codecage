| # | Plugin | Scenario | Threat | Expected | Actual | Reason | Wall ms | Verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | hello | policy | none (benign) | OK | OK |  | 14 | PASS |
| 2 | primes | policy | none (benign, CPU heavy) | OK | OK |  | 23 | PASS |
| 3 | linecount | policy grants demo_data | none (benign, file read) | OK | OK |  | 37 | PASS |
| 4 | linecount | no grant | reads a file it was not given | BLOCKED | BLOCKED | linecount failed: No such file or directory (os error 44) | 17 | PASS |
| 5 | infinite_loop | policy | CPU exhaustion | DENIED:cpu | DENIED:cpu | CPU budget exhausted (fuel limit 50000000) | 31 | PASS |
| 6 | infinite_loop | --no-fuel | CPU exhaustion, fuel off | DENIED:timeout | DENIED:timeout | timeout after 2000 ms | 2024 | PASS |
| 7 | mem_bomb | policy | memory exhaustion | DENIED:memory | DENIED:memory | memory limit of 64 MiB exceeded | 43 | PASS |
| 8 | read_ssh | policy | read SSH keys / system files | BLOCKED | BLOCKED | blocked /data/../.ssh/id_rsa: No such file or directory (os error 44) | 33 | PASS |
| 9 | escape_preopen | policy | path traversal (../) | BLOCKED | BLOCKED | blocked ../Cargo.toml: No such file or directory (os error 44) | 35 | PASS |
| 10 | env_snoop | policy | steal env vars / tokens | BLOCKED | BLOCKED | env_snoop: no environment visible (good) | 36 | PASS |
| 11 | try_write | policy (read-only dir) | write to read-only folder | BLOCKED | BLOCKED | write blocked: Operation not permitted (os error 63) | 29 | PASS |
| 12 | output_flood | policy | stdout flood | DENIED:output | DENIED:output | output limit of 64 KiB exceeded | 29 | PASS |
| 13 | sleep_forever | policy | hang in a host call | DENIED:timeout | DENIED:timeout | timeout after 500 ms (plugin was blocked in a host call) | 781 | PASS |
| 14 | hello | hash-pinned policy | none (verified file) | OK | OK |  | 16 | PASS |
| 15 | env_snoop | hello's pinned policy | swapped / tampered plugin | DENIED:hash | DENIED:hash | plugin hash mismatch: policy pins 19a73301a636d30c441bdff42681b574b95fe08b3b2a2c50e6448b498f07e692, file is 33aacd68e9c7d428b5b6df0c2303496edd6bbdecc005cc92a80f10f16e64e607 | 10 | PASS |
| 16 | sleep_forever | defaults | hang in a host call | DENIED:timeout | DENIED:timeout | timeout after 2000 ms (plugin was blocked in a host call) | 2264 | PASS |
| 17 | c_wordcount | C, policy grants demo_data | none (benign, C) | OK | OK |  | 45 | PASS |
| 18 | c_steal | C, policy | files + ../ + write + env (C) | BLOCKED | BLOCKED | blocked read /etc/passwd | 41 | PASS |
| 19 | c_spin | C, policy | CPU exhaustion (C) | DENIED:cpu | DENIED:cpu | CPU budget exhausted (fuel limit 50000000) | 26 | PASS |

**19 / 19 scenarios behaved as expected.**
