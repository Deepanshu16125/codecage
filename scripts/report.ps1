# CodeCage HTML report: turns results/eval.csv + results/bench.csv into one self-contained page.
# Usage (from repo root):  pwsh scripts/report.ps1 [-Fresh]   -> results/report.html
#   -Fresh re-runs eval.ps1 and bench.ps1 first.
param([switch]$Fresh)
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$ps = $(if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' })
if ($Fresh -or -not (Test-Path results/eval.csv)) { & $ps -NoProfile -ExecutionPolicy Bypass -File scripts/eval.ps1 | Out-Null }
if ($Fresh -or -not (Test-Path results/bench.csv)) { & $ps -NoProfile -ExecutionPolicy Bypass -File scripts/bench.ps1 | Out-Null }
$eval = Import-Csv results/eval.csv
$bench = Import-Csv results/bench.csv
function E($s) { [System.Net.WebUtility]::HtmlEncode("$s") }
$b = @{}; foreach ($r in $bench) { $b[$r.benchmark] = $r }
$pass = @($eval | Where-Object verdict -eq 'PASS').Count
$total = $eval.Count
$blocked = @($eval | Where-Object { $_.actual -ne 'OK' -and $_.verdict -eq 'PASS' }).Count
$speedup = [math]::Round([double]$b.hello_cold.median_ms / [double]$b.hello_warm.median_ms, 1)
$overhead = [math]::Round([double]$b.primes_fuel.median_ms / [double]$b.primes_native.median_ms, 2)
$fuel = [math]::Round(100 * ([double]$b.primes_fuel.median_ms - [double]$b.primes_nofuel.median_ms) / [double]$b.primes_nofuel.median_ms, 1)
$commit = (git rev-parse --short HEAD 2>$null)
$when = Get-Date -Format 'dd MMM yyyy, HH:mm'

$evalRows = ($eval | ForEach-Object {
  $cls = $(if ($_.actual -eq 'OK') { 'ok' } elseif ($_.actual -like 'DENIED*') { 'deny' } else { 'block' })
  $v = $(if ($_.verdict -eq 'PASS') { 'pass' } else { 'fail' })
  "<tr><td>$(E $_.plugin)</td><td>$(E $_.scenario)</td><td>$(E $_.threat)</td><td>$(E $_.expected)</td><td><span class='tag $cls'>$(E $_.actual)</span></td><td class='muted'>$(E $_.reason)</td><td class='num'>$(E $_.wall_ms)</td><td><span class='v $v'>$(E $_.verdict)</span></td></tr>"
}) -join "`n"

$max = ($bench | ForEach-Object { [double]$_.median_ms } | Measure-Object -Maximum).Maximum
$bars = ($bench | ForEach-Object {
  $w = [math]::Round(100 * [double]$_.median_ms / $max, 1)
  "<div class='bar'><div class='bl'>$(E $_.benchmark)<small>$(E $_.description)</small></div><div class='bt'><div class='bf' style='width:$w%'></div></div><div class='bv'>$(E $_.median_ms) ms</div></div>"
}) -join "`n"

$html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CodeCage - Evaluation Report</title>
<style>
:root{--bg:#0f1117;--card:#181b24;--line:#2a2f3d;--text:#e6e8ee;--muted:#9097a8;--ok:#3ecf8e;--deny:#ff6b6b;--block:#f5a524;--accent:#7c9cff}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--text)}
.wrap{max-width:1150px;margin:0 auto;padding:32px 20px}h1{margin:0;font-size:30px}h2{margin:36px 0 12px;font-size:20px}
.sub{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-top:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}.big{font-size:30px;font-weight:700}
.card .l{color:var(--muted);font-size:13px}table{width:100%;border-collapse:collapse;background:var(--card);border-radius:12px;overflow:hidden}
th,td{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;font-size:13.5px;vertical-align:top}th{color:var(--muted);font-weight:600}
.num{text-align:right}.muted{color:var(--muted)}.tag{padding:2px 8px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}
.tag.ok{background:#3ecf8e22;color:var(--ok)}.tag.deny{background:#ff6b6b22;color:var(--deny)}.tag.block{background:#f5a52422;color:var(--block)}
.v.pass{color:var(--ok);font-weight:700}.v.fail{color:var(--deny);font-weight:700}
.bar{display:grid;grid-template-columns:300px 1fr 80px;gap:12px;align-items:center;margin:10px 0}.bl small{display:block;color:var(--muted);font-size:12px}
.bt{background:var(--line);border-radius:6px;height:14px}.bf{background:var(--accent);height:14px;border-radius:6px}.bv{text-align:right;font-variant-numeric:tabular-nums}
ul{margin:8px 0;padding-left:20px}footer{margin-top:40px;color:var(--muted);font-size:12px}
</style></head><body><div class="wrap">
<h1>CodeCage</h1><div class="sub">A WebAssembly sandbox for untrusted plug-ins - evaluation report</div>
<div class="grid">
<div class="card"><div class="big">$pass / $total</div><div class="l">scenarios behaved as expected</div></div>
<div class="card"><div class="big">$blocked</div><div class="l">attacks blocked or stopped</div></div>
<div class="card"><div class="big">$speedup&times;</div><div class="l">faster startup with the compile cache</div></div>
<div class="card"><div class="big">$overhead&times;</div><div class="l">wall time vs native (primes, fuel on)</div></div>
<div class="card"><div class="big">$fuel%</div><div class="l">extra cost of fuel metering</div></div>
</div>
<h2>Security evaluation</h2>
<p class="sub">Each plugin runs under its own <code>codecage.toml</code> policy. <span class="tag ok">OK</span> = allowed and worked, <span class="tag block">BLOCKED</span> = the sandbox refused the file or env access, <span class="tag deny">DENIED</span> = a resource limit stopped the plugin.</p>
<table><thead><tr><th>Plugin</th><th>Scenario</th><th>Threat</th><th>Expected</th><th>Actual</th><th>Reason / plugin output</th><th class="num">ms</th><th>Verdict</th></tr></thead><tbody>
$evalRows
</tbody></table>
<h2>Performance</h2>
<p class="sub">Median whole-process wall time over $(E $b.hello_cold.runs) runs each.</p>
<div class="card">$bars</div>
<h2>How it is enforced</h2>
<div class="card"><ul>
<li><b>CPU</b>: wasmtime fuel metering, with a per-plugin budget.</li>
<li><b>Time</b>: epoch interruption plus a watchdog that hard-stops plugins stuck in host calls about 250 ms after the timeout.</li>
<li><b>Memory</b>: a resource limiter caps linear memory growth.</li>
<li><b>Output</b>: stdout and stderr are captured in capped buffers.</li>
<li><b>Files and environment</b>: capability-based WASI. A plugin sees only the folders its policy grants (read-only unless it says write) and only the named env vars.</li>
<li><b>Audit</b>: every run is logged; <code>codecage audit</code> summarizes denials per plugin.</li>
</ul></div>
<footer>Generated $when from commit $commit by scripts/report.ps1.</footer>
</div></body></html>
"@
[IO.File]::WriteAllText((Join-Path $root 'results/report.html'), $html)
Write-Host "wrote results/report.html"