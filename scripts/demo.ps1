# CodeCage live demo: good plugins work, malicious ones are stopped, then the audit summary and report.
# Usage (from repo root):  powershell -ExecutionPolicy Bypass -File scripts/demo.ps1 [-NoPause] [-OpenReport]
param([switch]$NoPause, [switch]$OpenReport)
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$exe = Join-Path $root 'target/release/codecage.exe'
if (-not ($IsWindows -or $env:OS -eq 'Windows_NT')) { $exe = Join-Path $root 'target/release/codecage' }
$wasm = Join-Path $root 'target/wasm32-wasip1/release'
$env:SECRET_TOKEN = 'hunter2'
$env:CODECAGE_LOG = Join-Path $root 'target/demo-audit.log'
if (Test-Path $env:CODECAGE_LOG) { Remove-Item $env:CODECAGE_LOG }

Write-Host 'Building CodeCage and the demo plugins...' -ForegroundColor DarkGray
cargo build --release -p host 2>&1 | Out-Null
cargo build --release --target wasm32-wasip1 --workspace --exclude host 2>&1 | Out-Null

$step = 0
function Step($title, $explain, $plugin, [string[]]$cageArgs, [int]$keepLines = 6) {
  $script:step++
  Write-Host ''
  Write-Host ("[{0}] {1}" -f $script:step, $title) -ForegroundColor Cyan
  Write-Host "    $explain" -ForegroundColor DarkGray
  Write-Host ("    > codecage run $plugin.wasm " + ($cageArgs -join ' ')) -ForegroundColor DarkYellow
  $lines = @(& $exe run (Join-Path $wasm "$plugin.wasm") @cageArgs 2>&1 | ForEach-Object { "$_" })
  $code = $LASTEXITCODE
  $shown = $lines | Where-Object { $_ -notmatch '^note: run with|^thread .* panicked|^\s*$' }
  if ($shown.Count -gt $keepLines) {
    $shown[0..1] | ForEach-Object { Write-Host "    $($_.Substring(0, [math]::Min(90, $_.Length)))" }
    Write-Host "    ... ($($shown.Count - $keepLines + 2) more lines hidden) ..." -ForegroundColor DarkGray
    $shown = $shown[-($keepLines - 2)..-1]
  }
  foreach ($l in $shown) {
    $t = $l.Substring(0, [math]::Min(110, $l.Length))
    $color = if ($l -match 'DENIED|LEAKED|ESCAPED|WROTE') { 'Red' } elseif ($l -match 'ok:|verified') { 'Green' } elseif ($l -match 'WARNING') { 'Yellow' } else { 'Gray' }
    Write-Host "    $t" -ForegroundColor $color
  }
  $verdict = switch ($code) { 0 { 'ALLOWED - ran normally' } 1 { 'BLOCKED - the sandbox refused the access' } 2 { 'DENIED - CodeCage stopped the plugin' } default { "exit $code" } }
  $vc = if ($code -eq 0) { 'Green' } else { 'Magenta' }
  Write-Host "    => $verdict" -ForegroundColor $vc
  if (-not $NoPause) { Read-Host '    (press Enter for the next step)' | Out-Null }
}

Write-Host ''
Write-Host '==============================================================' -ForegroundColor Cyan
Write-Host '  CodeCage - running untrusted plugins safely with WebAssembly' -ForegroundColor Cyan
Write-Host '  A plugin gets no files, no env vars, no network, and fixed' -ForegroundColor Cyan
Write-Host '  CPU / memory / time / output budgets unless its policy says so.' -ForegroundColor Cyan
Write-Host '==============================================================' -ForegroundColor Cyan

Step 'A normal plugin' 'Prints a greeting. Shows the fuel (CPU) it used.' 'hello' @('--policy', 'plugins/hello/codecage.toml')
Step 'Reading a file WITHOUT permission' 'linecount wants /data/sample.txt, but no folder was granted.' 'linecount' @()
Step 'Reading a file WITH permission' 'Its policy grants read-only access to demo_data.' 'linecount' @('--policy', 'plugins/linecount/codecage.toml')
Step 'Stealing SSH keys' 'read_ssh tries ~/.ssh/id_rsa, /etc/passwd and C:\Windows paths.' 'read_ssh' @('--policy', 'plugins/read_ssh/codecage.toml')
Step 'Escaping the granted folder' 'escape_preopen tries ../ to climb out of /data.' 'escape_preopen' @('--policy', 'plugins/escape_preopen/codecage.toml')
Step 'Stealing secrets from the environment' 'The host has SECRET_TOKEN=hunter2 set. env_snoop looks for it.' 'env_snoop' @('--policy', 'plugins/env_snoop/codecage.toml')
Step 'Writing to a read-only folder' 'try_write was given demo_data read-only and tries to create evil.txt.' 'try_write' @('--policy', 'plugins/try_write/codecage.toml')
Step 'Infinite loop' 'Burns CPU forever. The fuel budget stops it.' 'infinite_loop' @('--policy', 'plugins/infinite_loop/codecage.toml')
Step 'Memory bomb' 'Allocates memory until stopped. The 64 MiB cap stops it.' 'mem_bomb' @('--policy', 'plugins/mem_bomb/codecage.toml')
Step 'Output flood' 'Spams stdout. The 64 KiB output cap stops it.' 'output_flood' @('--policy', 'plugins/output_flood/codecage.toml') 4
Step 'Hanging in a system call' 'Sleeps for an hour inside the host. The watchdog hard-stops it.' 'sleep_forever' @('--policy', 'plugins/sleep_forever/codecage.toml')

if (Get-Command zig -ErrorAction SilentlyContinue) {
  & (Join-Path $PSScriptRoot 'build-c.ps1') | Out-Null
  $wasmRust = $wasm; $wasm = Join-Path $root 'target/c-plugins'
  Step 'A plugin written in C' 'Same cage, different language: C compiled to WebAssembly with Zig.' 'c_wordcount' @('--policy', 'plugins_c/c_wordcount/codecage.toml')
  Step 'A malicious C plugin' 'Tries /etc/passwd, SSH keys, ../ escape, a write, and SECRET_TOKEN.' 'c_steal' @('--policy', 'plugins_c/c_steal/codecage.toml') 9
  $wasm = $wasmRust
}

$pinDir = Join-Path $root 'target/demo-policies'; New-Item -ItemType Directory -Force $pinDir | Out-Null
$h = ((& $exe hash (Join-Path $wasm 'hello.wasm')) -split '\s+')[0]
$pin = Join-Path $pinDir 'hello_pinned.toml'
[IO.File]::WriteAllText($pin, "sha256 = `"$h`"`n")
Step 'Hash pinning: the right file' "Policy pinned to hello.wasm (sha256 $($h.Substring(0,12))...)." 'hello' @('--policy', $pin)
Step 'Hash pinning: a swapped file' 'Same policy, but someone replaced the plugin with env_snoop.' 'env_snoop' @('--policy', $pin)

Write-Host ''
Write-Host "[$($step + 1)] Audit log - every run above was recorded" -ForegroundColor Cyan
& $exe audit 2>&1 | ForEach-Object { Write-Host "    $_" }

if ($OpenReport) {
  $ps = $(if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' })
  & $ps -NoProfile -ExecutionPolicy Bypass -File scripts/report.ps1 | Out-Null
  Start-Process (Join-Path $root 'results/report.html')
}
Write-Host ''
Write-Host 'Demo finished.' -ForegroundColor Green