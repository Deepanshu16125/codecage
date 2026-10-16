# CodeCage evaluation table: runs every plugin/scenario and records what the sandbox did.
# Usage (from repo root):  pwsh scripts/eval.ps1      -> results/eval.csv and results/eval.md
$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
cargo build --release -p host 2>&1 | Out-Null
cargo build --release --target wasm32-wasip1 --workspace --exclude host 2>&1 | Out-Null
$exe = Join-Path $root 'target/release/codecage'
if ($IsWindows -or $env:OS -eq 'Windows_NT') { $exe += '.exe' }
$wasm = Join-Path $root 'target/wasm32-wasip1/release'
$env:SECRET_TOKEN = 'hunter2'   # a fake secret the env test tries to steal
$env:CODECAGE_LOG = Join-Path $root 'target/eval-audit.log'

function Pol($p) { "plugins/$p/codecage.toml" }

# Hash-pinned policies, generated fresh because the hash changes on every rebuild.
$pinDir = Join-Path $root 'target/eval-policies'
New-Item -ItemType Directory -Force $pinDir | Out-Null
$helloHash = ((& $exe hash (Join-Path $wasm 'hello.wasm')) -split '\s+')[0]
$pinned = Join-Path $pinDir 'hello_pinned.toml'
[IO.File]::WriteAllText($pinned, "sha256 = `"$helloHash`"`n")

# plugin, scenario, threat, expected (OK | BLOCKED | DENIED:<limit>), args
$cases = @(
  @('hello',          'policy',                 'none (benign)',             'OK',              @('--policy', (Pol 'hello'))),
  @('primes',         'policy',                 'none (benign, CPU heavy)',  'OK',              @('--policy', (Pol 'primes'))),
  @('linecount',      'policy grants demo_data','none (benign, file read)',  'OK',              @('--policy', (Pol 'linecount'))),
  @('linecount',      'no grant',               'reads a file it was not given', 'BLOCKED',     @()),
  @('infinite_loop',  'policy',                 'CPU exhaustion',            'DENIED:cpu',      @('--policy', (Pol 'infinite_loop'))),
  @('infinite_loop',  '--no-fuel',              'CPU exhaustion, fuel off',  'DENIED:timeout',  @('--no-fuel')),
  @('mem_bomb',       'policy',                 'memory exhaustion',         'DENIED:memory',   @('--policy', (Pol 'mem_bomb'))),
  @('read_ssh',       'policy',                 'read SSH keys / system files', 'BLOCKED',      @('--policy', (Pol 'read_ssh'))),
  @('escape_preopen', 'policy',                 'path traversal (../)',      'BLOCKED',         @('--policy', (Pol 'escape_preopen'))),
  @('env_snoop',      'policy',                 'steal env vars / tokens',   'BLOCKED',         @('--policy', (Pol 'env_snoop'))),
  @('try_write',      'policy (read-only dir)', 'write to read-only folder', 'BLOCKED',         @('--policy', (Pol 'try_write'))),
  @('output_flood',   'policy',                 'stdout flood',              'DENIED:output',   @('--policy', (Pol 'output_flood'))),
  @('sleep_forever',  'policy',                 'hang in a host call',       'DENIED:timeout',  @('--policy', (Pol 'sleep_forever'))),
  @('hello',          'hash-pinned policy',     'none (verified file)',      'OK',              @('--policy', $pinned)),
  @('env_snoop',      'hello''s pinned policy', 'swapped / tampered plugin', 'DENIED:hash',     @('--policy', $pinned)),
  @('sleep_forever',  'defaults',               'hang in a host call',       'DENIED:timeout',  @())
)

# C plugins (second language), built with Zig when available.
$cdir = Join-Path $root 'target/c-plugins'
if (Get-Command zig -ErrorAction SilentlyContinue) {
  & (Join-Path $PSScriptRoot 'build-c.ps1') | Out-Null
  $cases += ,@('c_wordcount', 'C, policy grants demo_data', 'none (benign, C)', 'OK', @('--policy', 'plugins_c/c_wordcount/codecage.toml'))
  $cases += ,@('c_steal', 'C, policy', 'files + ../ + write + env (C)', 'BLOCKED', @('--policy', 'plugins_c/c_steal/codecage.toml'))
  $cases += ,@('c_spin', 'C, policy', 'CPU exhaustion (C)', 'DENIED:cpu', @('--policy', 'plugins_c/c_spin/codecage.toml'))
}

function Category($reason) {
  if ($reason -match 'hash') { 'hash' } elseif ($reason -match 'fuel') { 'cpu' } elseif ($reason -match 'timeout') { 'timeout' }
  elseif ($reason -match 'memory') { 'memory' } elseif ($reason -match 'output') { 'output' } else { 'other' }
}

$rows = foreach ($c in $cases) {
  $plugin, $scenario, $threat, $expected, $extra = $c
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $text = (& $exe run $(if ($plugin -like 'c_*') { Join-Path $cdir "$plugin.wasm" } else { Join-Path $wasm "$plugin.wasm" }) @extra 2>&1 | ForEach-Object { "$_" }) -join "`n"
  $code = $LASTEXITCODE
  $sw.Stop()
  $leak = $text -match 'LEAKED|ESCAPED|WROTE'
  $reason = ''
  if ($code -eq 0) { $actual = 'OK' }
  elseif ($code -eq 2 -and $text -match '\[codecage\] DENIED: (.+)') { $reason = $Matches[1].Trim(); $actual = 'DENIED:' + (Category $reason) }
  elseif ($code -eq 1 -and -not $leak) { $actual = 'BLOCKED'; $reason = (($text -split "`n") | Where-Object { $_ -notmatch '^\[codecage\]' } | Select-Object -First 1) }
  else { $actual = "EXIT $code" }
  if ($leak) { $actual = 'LEAKED' }
  [pscustomobject]@{
    plugin = $plugin; scenario = $scenario; threat = $threat; expected = $expected; actual = $actual
    exit_code = $code; reason = $reason; wall_ms = [math]::Round($sw.Elapsed.TotalMilliseconds)
    verdict = $(if ($actual -eq $expected) { 'PASS' } else { 'FAIL' })
  }
}

New-Item -ItemType Directory -Force (Join-Path $root 'results') | Out-Null
$rows | Export-Csv -NoTypeInformation -Encoding utf8 (Join-Path $root 'results/eval.csv')
$md = @('| # | Plugin | Scenario | Threat | Expected | Actual | Reason | Wall ms | Verdict |', '|---|---|---|---|---|---|---|---|---|')
$i = 0
foreach ($r in $rows) { $i++; $md += "| $i | $($r.plugin) | $($r.scenario) | $($r.threat) | $($r.expected) | $($r.actual) | $($r.reason -replace '\|','/') | $($r.wall_ms) | $($r.verdict) |" }
$pass = @($rows | Where-Object verdict -eq 'PASS').Count
$md += ''; $md += "**$pass / $($rows.Count) scenarios behaved as expected.**"
[IO.File]::WriteAllText((Join-Path $root 'results/eval.md'), ($md -join "`n") + "`n")
$rows | Format-Table plugin, scenario, expected, actual, wall_ms, verdict -AutoSize | Out-String -Width 200 | Write-Host
Write-Host "$pass / $($rows.Count) PASS  ->  results/eval.csv, results/eval.md"
if ($pass -ne $rows.Count) { exit 1 }