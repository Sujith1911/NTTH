$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$runtimeDir = Join-Path $root ".runtime"

foreach ($name in @("backend.pid", "web.pid")) {
    $pidFile = Join-Path $runtimeDir $name
    if (-not (Test-Path $pidFile)) {
        continue
    }

    $pidValue = Get-Content $pidFile -ErrorAction SilentlyContinue
    if ($pidValue) {
        $proc = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
        if ($proc) {
            Stop-Process -Id $pidValue -Force
        }
    }

    Remove-Item $pidFile -ErrorAction SilentlyContinue
}

Write-Host "Realtime test processes stopped."
