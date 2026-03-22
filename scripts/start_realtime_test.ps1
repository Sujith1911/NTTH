$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$runtimeDir = Join-Path $root ".runtime"
$backendDir = Join-Path $root "backend"
$flutterWebDir = Join-Path $root "flutter_app\\build\\web"

New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null

$backendPidFile = Join-Path $runtimeDir "backend.pid"
$webPidFile = Join-Path $runtimeDir "web.pid"

function Stop-IfRunning {
    param([string]$PidFile)

    if (Test-Path $PidFile) {
        $pidValue = Get-Content $PidFile -ErrorAction SilentlyContinue
        if ($pidValue) {
            $proc = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
            if ($proc) {
                Stop-Process -Id $pidValue -Force
            }
        }
        Remove-Item $PidFile -ErrorAction SilentlyContinue
    }
}

Stop-IfRunning -PidFile $backendPidFile
Stop-IfRunning -PidFile $webPidFile

$backendOut = Join-Path $runtimeDir "backend.out.log"
$backendErr = Join-Path $runtimeDir "backend.err.log"
$webOut = Join-Path $runtimeDir "web.out.log"
$webErr = Join-Path $runtimeDir "web.err.log"

$backendCmd = "py -3.12 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 1>> `"$backendOut`" 2>> `"$backendErr`""
$backend = Start-Process `
    -FilePath "cmd.exe" `
    -ArgumentList "/c", $backendCmd `
    -WorkingDirectory $backendDir `
    -WindowStyle Hidden `
    -PassThru

Set-Content -Path $backendPidFile -Value $backend.Id

$web = Start-Process py `
    -ArgumentList "-3.12","-m","http.server","8080","--bind","127.0.0.1" `
    -WorkingDirectory $flutterWebDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $webOut `
    -RedirectStandardError $webErr `
    -PassThru

Set-Content -Path $webPidFile -Value $web.Id

Write-Host "Backend: http://127.0.0.1:8000"
Write-Host "Flutter Web: http://127.0.0.1:8080"
Write-Host "Backend PID: $($backend.Id)"
Write-Host "Web PID: $($web.Id)"
