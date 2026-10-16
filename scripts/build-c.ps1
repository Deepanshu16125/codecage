# Build the C plugins to WebAssembly (wasm32-wasi) with Zig's bundled clang + wasi-libc.
# Usage (from repo root):  powershell -ExecutionPolicy Bypass -File scripts/build-c.ps1
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
if (-not (Get-Command zig -ErrorAction SilentlyContinue)) { Write-Error 'zig not found (winget install zig.zig)'; exit 1 }
$out = Join-Path $root 'target/c-plugins'
New-Item -ItemType Directory -Force $out | Out-Null
foreach ($d in Get-ChildItem plugins_c -Directory) {
  $dst = Join-Path $out "$($d.Name).wasm"
  # Zig's default initial memory is larger than our 16 MiB policy caps, so start small (1 MiB, 64 KiB stack) and grow on demand.
  zig cc -target wasm32-wasi -O2 -s '-Wl,--initial-memory=1048576' '-Wl,-z,stack-size=65536' -o $dst (Join-Path $d.FullName 'main.c')
  if ($LASTEXITCODE -ne 0) { Write-Error "failed to build $($d.Name)"; exit 1 }
  Write-Host ("built {0}  ({1:N0} bytes)" -f $dst, (Get-Item $dst).Length)
}