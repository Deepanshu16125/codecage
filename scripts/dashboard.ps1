# CodeCage live dashboard: a local web page to run any plugin (or all of them) and watch the results.
# Usage (from repo root):  powershell -ExecutionPolicy Bypass -File scripts/dashboard.ps1 [-Port 8765] [-NoBrowser]
# Stop with Ctrl+C or the "Stop server" button.
param([int]$Port = 8765, [switch]$NoBrowser)
$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$exe = Join-Path $root 'target/release/codecage.exe'
$rustDir = Join-Path $root 'target/wasm32-wasip1/release'
$cDir = Join-Path $root 'target/c-plugins'
$env:SECRET_TOKEN = 'hunter2'
$env:CODECAGE_LOG = Join-Path $root 'target/dashboard-audit.log'

Write-Host 'Building CodeCage and plugins (first time can take a minute)...' -ForegroundColor DarkGray
cargo build --release -p host 2>&1 | Out-Null
cargo build --release --target wasm32-wasip1 --workspace --exclude host 2>&1 | Out-Null
$hasZig = [bool](Get-Command zig -ErrorAction SilentlyContinue)
if ($hasZig) { & (Join-Path $PSScriptRoot 'build-c.ps1') | Out-Null }

$benign = @('hello', 'primes', 'linecount', 'c_wordcount')
$expected = @{
  hello = 'OK'; primes = 'OK'; linecount = 'OK'; c_wordcount = 'OK'
  infinite_loop = 'DENIED'; c_spin = 'DENIED'; mem_bomb = 'DENIED'; output_flood = 'DENIED'; sleep_forever = 'DENIED'
  read_ssh = 'BLOCKED'; escape_preopen = 'BLOCKED'; env_snoop = 'BLOCKED'; try_write = 'BLOCKED'; c_steal = 'BLOCKED'
}
$plugins = @()
foreach ($set in @(@('plugins', 'Rust', $rustDir), @('plugins_c', 'C', $cDir))) {
  $dir, $lang, $wdir = $set
  if (-not (Test-Path $dir)) { continue }
  foreach ($d in Get-ChildItem $dir -Directory | Sort-Object Name) {
    $wasm = Join-Path $wdir "$($d.Name).wasm"
    if (-not (Test-Path $wasm)) { continue }
    $pol = Join-Path $d.FullName 'codecage.toml'
    $desc = ''
    if (Test-Path $pol) { $m = Select-String -Path $pol -Pattern '^description\s*=\s*"(.*)"' | Select-Object -First 1; if ($m) { $desc = $m.Matches[0].Groups[1].Value } }
    $plugins += [pscustomobject]@{
      name = $d.Name; lang = $lang; kind = $(if ($benign -contains $d.Name) { 'benign' } else { 'malicious' })
      description = $desc; expected = $expected[$d.Name]; wasm = $wasm; policy = $pol
    }
  }
}
$byName = @{}; foreach ($p in $plugins) { $byName[$p.name] = $p }

function Run-Plugin($q) {
  $p = $byName[$q['name']]
  if (-not $p) { return @{ error = 'unknown plugin' } }
  $a = @('run', $p.wasm)
  if ($q['mode'] -ne 'none' -and (Test-Path $p.policy)) { $a += @('--policy', $p.policy) }
  foreach ($k in 'fuel', 'memory-mb', 'timeout-ms') { if ($q[$k] -match '^\d+$') { $a += @("--$k", $q[$k]) } }
  if ($q['nofuel'] -eq '1') { $a += '--no-fuel' }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $lines = @(& $exe @a 2>&1 | ForEach-Object { "$_" })
  $code = $LASTEXITCODE
  $sw.Stop()
  $text = ($lines | Where-Object { $_ -notmatch '^note: run with|^\s*System\.Management' }) -join "`n"
  $leak = $text -match 'LEAKED|ESCAPED|WROTE'
  $reason = ''
  if ($code -eq 0) { $verdict = 'OK' }
  elseif ($code -eq 2 -and $text -match '\[codecage\] DENIED: (.+)') { $verdict = 'DENIED'; $reason = $Matches[1].Trim() }
  elseif ($code -eq 1 -and -not $leak) { $verdict = 'BLOCKED'; $reason = 'plugin was refused file/env access' }
  else { $verdict = "EXIT $code" }
  if ($leak) { $verdict = 'LEAKED' }
  $fuel = $(if ($text -match 'fuel used (\d+)') { [long]$Matches[1] } else { $null })
  if ($text.Length -gt 6000) { $text = $text.Substring(0, 2500) + "`n... [$($text.Length - 5000) characters hidden] ...`n" + $text.Substring($text.Length - 2500) }
  @{ name = $p.name; verdict = $verdict; expected = $p.expected; reason = $reason; exit = $code; ms = [math]::Round($sw.Elapsed.TotalMilliseconds)
     fuel = $fuel; command = 'codecage ' + (($a | ForEach-Object { $_.Replace($root + '\', '') }) -join ' '); output = $text }
}

$html = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'dashboard.html'))
$listener = [Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()
$url = "http://localhost:$Port/"
Write-Host "CodeCage dashboard running at $url  (Ctrl+C to stop)" -ForegroundColor Green
if (-not $NoBrowser) { Start-Process $url }

function Reply($ctx, $body, $type = 'application/json') {
  $bytes = [Text.Encoding]::UTF8.GetBytes($body)
  $ctx.Response.ContentType = "$type; charset=utf-8"
  $ctx.Response.Headers.Add('Cache-Control', 'no-store')
  $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
  $ctx.Response.Close()
}

$running = $true
try {
  while ($running -and $listener.IsListening) {
    $ar = $listener.BeginGetContext($null, $null)
    while (-not $ar.AsyncWaitHandle.WaitOne(300)) { }
    $ctx = $listener.EndGetContext($ar)
    $path = $ctx.Request.Url.AbsolutePath
    $q = $ctx.Request.QueryString
    try {
      switch ($path) {
        '/' { Reply $ctx $html 'text/html' }
        '/api/plugins' { Reply $ctx (ConvertTo-Json @($plugins | Select-Object name, lang, kind, description, expected) -Depth 3) }
        '/api/run' { Reply $ctx (ConvertTo-Json (Run-Plugin $q) -Depth 3) }
        '/api/policy' {
          $p = $byName[$q['name']]
          $t = $(if ($p -and (Test-Path $p.policy)) { [IO.File]::ReadAllText($p.policy) } else { '(no policy file)' })
          Reply $ctx (ConvertTo-Json @{ text = $t })
        }
        '/api/inspect' {
          $p = $byName[$q['name']]
          $t = (& $exe inspect $p.wasm 2>&1 | ForEach-Object { "$_" }) -join "`n"
          Reply $ctx (ConvertTo-Json @{ text = $t.Replace($root + '\', '') })
        }
        '/api/audit' {
          if ($q['clear'] -eq '1') { & $exe audit --clear | Out-Null }
          $t = (& $exe audit 2>&1 | ForEach-Object { "$_" }) -join "`n"
          Reply $ctx (ConvertTo-Json @{ text = $t })
        }
        '/api/quit' { Reply $ctx '{"ok":true}'; $running = $false }
        default { $ctx.Response.StatusCode = 404; Reply $ctx '{"error":"not found"}' }
      }
    } catch {
      try { $ctx.Response.StatusCode = 500; Reply $ctx (ConvertTo-Json @{ error = "$_" }) } catch { }
    }
  }
} finally {
  $listener.Stop()
  Write-Host 'Dashboard stopped.'
}