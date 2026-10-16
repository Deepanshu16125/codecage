# CodeCage benchmarks: startup (cold vs warm cache), wasm vs native, and the cost of fuel metering.
# Usage (from repo root):  pwsh scripts/bench.ps1 [-Runs 20]   -> results/bench.csv and results/bench.md
param([int]$Runs = 20)
$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$win = ($IsWindows -or $env:OS -eq 'Windows_NT')
$ext = $(if ($win) { '.exe' } else { '' })
cargo build --release -p host 2>&1 | Out-Null
cargo build --release --target wasm32-wasip1 --workspace --exclude host 2>&1 | Out-Null
cargo build --release -p primes 2>&1 | Out-Null          # native build of the same plugin source
$exe = Join-Path $root "target/release/codecage$ext"
$wasm = Join-Path $root 'target/wasm32-wasip1/release'
$native = Join-Path $root "target/release/primes$ext"
$cache = $(if ($win) { Join-Path $env:LOCALAPPDATA 'codecage/cache' } else { Join-Path $HOME '.cache/codecage' })
$env:CODECAGE_LOG = Join-Path $root 'target/bench-audit.log'

function Stats($name, $desc, [double[]]$wall, [double[]]$inner) {
  $s = $wall | Sort-Object
  $n = $s.Count
  $p95 = $s[[math]::Min($n - 1, [math]::Ceiling(0.95 * $n) - 1)]
  $med = $(if ($n % 2) { $s[($n - 1) / 2] } else { ($s[$n / 2 - 1] + $s[$n / 2]) / 2 })
  $innerMed = ''
  if ($inner.Count) { $si = $inner | Sort-Object; $innerMed = $si[[int](($si.Count - 1) / 2)] }
  [pscustomobject]@{ benchmark = $name; description = $desc; runs = $n
    median_ms = [math]::Round($med, 1); min_ms = [math]::Round($s[0], 1); p95_ms = [math]::Round($p95, 1)
    exec_ms_median = $innerMed }
}

function Time-Bench($name, $desc, [scriptblock]$before, [string]$cmd, [string[]]$cmdArgs) {
  & $cmd @cmdArgs 2>&1 | Out-Null   # warm-up (not counted)
  $wall = @(); $inner = @()
  for ($i = 0; $i -lt $Runs; $i++) {
    if ($before) { & $before }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $text = (& $cmd @cmdArgs 2>&1 | ForEach-Object { "$_" }) -join "`n"
    $sw.Stop()
    $wall += $sw.Elapsed.TotalMilliseconds
    if ($text -match 'time (\d+) ms') { $inner += [double]$Matches[1] }
  }
  Stats $name $desc $wall $inner
}

$clear = { if (Test-Path $cache) { Remove-Item -Recurse -Force $cache } }
$rows = @(
  (Time-Bench 'hello_cold'    'hello, compile cache cleared before every run' $clear $exe @('run', "$wasm/hello.wasm")),
  (Time-Bench 'hello_warm'    'hello, compiled module loaded from cache'      $null  $exe @('run', "$wasm/hello.wasm")),
  (Time-Bench 'primes_fuel'   'primes to 2M in the cage, fuel metering on'    $null  $exe @('run', "$wasm/primes.wasm", '--fuel', '1000000000')),
  (Time-Bench 'primes_nofuel' 'primes to 2M in the cage, --no-fuel'           $null  $exe @('run', "$wasm/primes.wasm", '--no-fuel')),
  (Time-Bench 'primes_native' 'same primes source built as a native program'  $null  $native @())
)

New-Item -ItemType Directory -Force (Join-Path $root 'results') | Out-Null
$rows | Export-Csv -NoTypeInformation -Encoding utf8 (Join-Path $root 'results/bench.csv')
$byName = @{}; foreach ($r in $rows) { $byName[$r.benchmark] = $r }
$speedup = [math]::Round($byName.hello_cold.median_ms / [math]::Max(0.1, $byName.hello_warm.median_ms), 1)
$overhead = [math]::Round($byName.primes_fuel.median_ms / [math]::Max(0.1, $byName.primes_native.median_ms), 2)
$fuelCost = [math]::Round(100 * ($byName.primes_fuel.median_ms - $byName.primes_nofuel.median_ms) / [math]::Max(0.1, $byName.primes_nofuel.median_ms), 1)
$cpu = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1).Name
$md = @("Machine: $cpu, $Runs runs each (plus one warm-up). Times are whole-process wall-clock ms; exec ms is the plugin's own run time reported by codecage.", '',
        '| Benchmark | What it measures | Median ms | Min ms | p95 ms | Exec ms (median) |', '|---|---|---|---|---|---|')
foreach ($r in $rows) { $md += "| $($r.benchmark) | $($r.description) | $($r.median_ms) | $($r.min_ms) | $($r.p95_ms) | $($r.exec_ms_median) |" }
$md += ''
$md += "- Compile cache makes startup **$speedup x** faster (cold vs warm median)."
$md += "- Caged primes (with fuel) takes **$overhead x** the wall time of the native program."
$md += "- Fuel metering costs **$fuelCost %** wall time on primes versus --no-fuel."
[IO.File]::WriteAllText((Join-Path $root 'results/bench.md'), ($md -join "`n") + "`n")
$rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
$md[-3..-1] | Write-Host