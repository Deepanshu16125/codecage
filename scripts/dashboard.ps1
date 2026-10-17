# CodeCage live dashboard: a local web page to run any plugin (or all of them) and watch the results.
# Usage (from repo root):  powershell -ExecutionPolicy Bypass -File scripts/dashboard.ps1 [-Port 8765] [-NoBrowser]
# Stop with Ctrl+C or the "Stop server" button.
# Runs are non-blocking: each plugin runs as its own codecage process (a "job"), so the page stays
# responsive while a slow plugin (e.g. infinite_loop with --no-fuel and a long timeout) is running.
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

# ---- jobs: one codecage process per run ----
$jobs = [Collections.Generic.SortedDictionary[int, object]]::new()
$script:nextId = 1

function Format-Arg([string]$s) { if ($s -match '[\s"]') { '"' + ($s -replace '"', '\"') + '"' } else { $s } }

function Start-PluginJob($q) {
  $p = $byName[$q['name']]
  if (-not $p) { return @{ error = 'unknown plugin' } }
  $a = @('run', $p.wasm)
  if ($q['mode'] -ne 'none' -and (Test-Path $p.policy)) { $a += @('--policy', $p.policy) }
  $custom = $q['mode'] -eq 'none'
  foreach ($k in 'fuel', 'memory-mb', 'timeout-ms') { if ($q[$k] -match '^\d+$') { $a += @("--$k", $q[$k]); $custom = $true } }
  if ($q['nofuel'] -eq '1') { $a += '--no-fuel'; $custom = $true }
  $psi = [Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $exe
  $psi.Arguments = ($a | ForEach-Object { Format-Arg $_ }) -join ' '
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $proc = [Diagnostics.Process]::Start($psi)
  $j = @{
    id = $script:nextId; name = $p.name; expected = $p.expected; label = "$($q['label'])"; custom = $custom
    command = 'codecage ' + (($a | ForEach-Object { $_.Replace($root + '\', '') }) -join ' ')
    proc = $proc; sw = [Diagnostics.Stopwatch]::StartNew()
    out = $proc.StandardOutput.ReadToEndAsync(); err = $proc.StandardError.ReadToEndAsync()
    status = 'running'; cancelled = $false; result = $null
  }
  $script:nextId++
  $jobs[$j.id] = $j
  Get-JobView $j $false
}

function Complete-PluginJob($j) {
  if ($j.status -ne 'running') { return }
  if (-not $j.proc.HasExited) { return }
  if (-not ($j.out.IsCompleted -and $j.err.IsCompleted)) { return }
  $j.sw.Stop()
  $ms = [math]::Round($j.sw.Elapsed.TotalMilliseconds)
  try { $ms = [math]::Round(($j.proc.ExitTime - $j.proc.StartTime).TotalMilliseconds) } catch { }
  $code = $j.proc.ExitCode
  $raw = ($j.out.Result + "`n" + $j.err.Result) -replace "`r`n", "`n"
  $text = (($raw -split "`n") | Where-Object { $_ -notmatch '^note: run with' }) -join "`n"
  $text = $text.Trim("`n")
  $leak = $text -match 'LEAKED|ESCAPED|WROTE'
  $reason = ''
  if ($j.cancelled) { $verdict = 'CANCELLED'; $reason = "stopped from the dashboard after $ms ms" }
  elseif ($code -eq 0) { $verdict = 'OK' }
  elseif ($code -eq 2 -and $text -match '\[codecage\] DENIED: (.+)') { $verdict = 'DENIED'; $reason = $Matches[1].Trim() }
  elseif ($code -eq 1 -and -not $leak) { $verdict = 'BLOCKED'; $reason = 'plugin was refused file/env access' }
  else { $verdict = "EXIT $code" }
  if ($leak) { $verdict = 'LEAKED' }
  $fuel = $(if ($text -match 'fuel used (\d+)') { [long]$Matches[1] } else { $null })
  if ($text.Length -gt 6000) { $text = $text.Substring(0, 2500) + "`n... [$($text.Length - 5000) characters hidden] ...`n" + $text.Substring($text.Length - 2500) }
  $j.result = @{ verdict = $verdict; reason = $reason; exit = $code; ms = $ms; fuel = $fuel; output = $text }
  $j.status = 'done'
  $j.proc.Dispose()
}

function Get-JobView($j, [bool]$full) {
  $v = @{ id = $j.id; name = $j.name; expected = $j.expected; label = $j.label; custom = $j.custom; command = $j.command; status = $j.status }
  if ($j.status -eq 'running') { $v.verdict = 'running'; $v.ms = [math]::Round($j.sw.Elapsed.TotalMilliseconds) }
  else {
    foreach ($k in 'verdict', 'reason', 'exit', 'ms', 'fuel') { $v[$k] = $j.result[$k] }
    if ($full) { $v.output = $j.result.output }
  }
  $v
}

function Stop-PluginJob($j) {
  if ($j.status -ne 'running') { return }
  $j.cancelled = $true
  try { if (-not $j.proc.HasExited) { & taskkill.exe /T /F /PID $j.proc.Id 2>&1 | Out-Null } } catch { }
  try { [void]$j.proc.WaitForExit(2000) } catch { }
  [void][Threading.Tasks.Task]::WaitAll(@($j.out, $j.err), 2000)
  Complete-PluginJob $j
}

function Update-AllJobs { foreach ($j in @($jobs.Values)) { Complete-PluginJob $j } }

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
function ToJson($o) { ConvertTo-Json -InputObject $o -Depth 4 -Compress }

$running = $true
try {
  while ($running -and $listener.IsListening) {
    $ar = $listener.BeginGetContext($null, $null)
    while (-not $ar.AsyncWaitHandle.WaitOne(200)) { Update-AllJobs }
    $ctx = $listener.EndGetContext($ar)
    $path = $ctx.Request.Url.AbsolutePath
    $q = $ctx.Request.QueryString
    try {
      Update-AllJobs
      switch ($path) {
        '/' { Reply $ctx $html 'text/html' }
        '/api/plugins' { Reply $ctx (ToJson @($plugins | Select-Object name, lang, kind, description, expected)) }
        '/api/run' { Reply $ctx (ToJson (Start-PluginJob $q)) }
        '/api/job' {
          $j = $null; [void]$jobs.TryGetValue([int]$q['id'], [ref]$j)
          if (-not $j) { $ctx.Response.StatusCode = 404; Reply $ctx '{"error":"no such job"}' } else { Reply $ctx (ToJson (Get-JobView $j $true)) }
        }
        '/api/jobs' { Reply $ctx (ToJson @($jobs.Values | ForEach-Object { Get-JobView $_ $false })) }
        '/api/cancel' {
          if ($q['all'] -eq '1') { $todo = @($jobs.Values | Where-Object { $_.status -eq 'running' }) }
          else { $j = $null; [void]$jobs.TryGetValue([int]$q['id'], [ref]$j); $todo = @($j | Where-Object { $_ }) }
          foreach ($j in $todo) { Stop-PluginJob $j }
          Reply $ctx (ToJson @{ cancelled = @($todo | ForEach-Object { $_.id }) })
        }
        '/api/clear' {
          foreach ($j in @($jobs.Values | Where-Object { $_.status -eq 'done' })) { [void]$jobs.Remove($j.id) }
          Reply $ctx '{"ok":true}'
        }
        '/api/policy' {
          $p = $byName[$q['name']]
          $t = $(if ($p -and (Test-Path $p.policy)) { [IO.File]::ReadAllText($p.policy) } else { '(no policy file)' })
          Reply $ctx (ToJson @{ text = $t })
        }
        '/api/inspect' {
          $p = $byName[$q['name']]
          $t = (& $exe inspect $p.wasm 2>&1 | ForEach-Object { "$_" }) -join "`n"
          Reply $ctx (ToJson @{ text = $t.Replace($root + '\', '') })
        }
        '/api/audit' {
          if ($q['clear'] -eq '1') { & $exe audit --clear | Out-Null }
          $t = (& $exe audit 2>&1 | ForEach-Object { "$_" }) -join "`n"
          Reply $ctx (ToJson @{ text = $t })
        }
        '/api/quit' {
          foreach ($j in @($jobs.Values | Where-Object { $_.status -eq 'running' })) { Stop-PluginJob $j }
          Reply $ctx '{"ok":true}'; $running = $false
        }
        default { $ctx.Response.StatusCode = 404; Reply $ctx '{"error":"not found"}' }
      }
    } catch {
      try { $ctx.Response.StatusCode = 500; Reply $ctx (ToJson @{ error = "$_" }) } catch { }
    }
  }
} finally {
  foreach ($j in @($jobs.Values | Where-Object { $_.status -eq 'running' })) { Stop-PluginJob $j }
  $listener.Stop()
  Write-Host 'Dashboard stopped.'
}
