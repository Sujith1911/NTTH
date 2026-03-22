$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$backendRoot = Join-Path $projectRoot "backend"
$startScript = Join-Path $PSScriptRoot "start_host_backend.ps1"
$logsDir = Join-Path $backendRoot "logs"
$stdoutLog = Join-Path $logsDir "host_backend_stdout.log"
$stderrLog = Join-Path $logsDir "host_backend_stderr.log"

New-Item -ItemType Directory -Force -Path $logsDir | Out-Null
if (Test-Path $stdoutLog) { Remove-Item $stdoutLog -Force }
if (Test-Path $stderrLog) { Remove-Item $stderrLog -Force }

Write-Host "Recreating support containers (Postgres + Cowrie) with host log mount..."
Push-Location $backendRoot
docker compose up -d postgres cowrie
docker compose stop backend
Pop-Location

Write-Host "Starting backend locally for host-native realtime capture..."
Start-Process cmd.exe `
    -WindowStyle Minimized `
    -WorkingDirectory $projectRoot `
    -ArgumentList "/c powershell -ExecutionPolicy Bypass -File `"$startScript`" 1>> `"$stdoutLog`" 2>> `"$stderrLog`""
