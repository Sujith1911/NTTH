$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$backendRoot = Join-Path $projectRoot "backend"
$cowrieLogs = Join-Path $backendRoot "cowrie\\logs"
New-Item -ItemType Directory -Force -Path $cowrieLogs | Out-Null

function Get-LocalIpv4 {
    try {
        $socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
        $socket.Connect("8.8.8.8", 80)
        $ip = ($socket.LocalEndPoint).Address.ToString()
        $socket.Close()
        return $ip
    } catch {
        return "127.0.0.1"
    }
}

function Get-GatewayIp {
    try {
        $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
            Sort-Object RouteMetric, InterfaceMetric |
            Select-Object -First 1
        if ($route.NextHop) {
            return $route.NextHop
        }
    } catch {
    }
    return "192.168.1.1"
}

$serverIp = Get-LocalIpv4
$gatewayIp = Get-GatewayIp
$scanSubnet = if ($serverIp -match '^(\d+\.\d+\.\d+)\.\d+$') { "$($Matches[1]).0/24" } else { "" }

$env:DATABASE_URL = "postgresql+asyncpg://ntth_user:changeme@127.0.0.1:5432/ntth"
$env:SECRET_KEY = "super-secret-change-in-production"
$env:ADMIN_PASSWORD = "changeme"
$env:ENVIRONMENT = "development"
$env:DEBUG = "true"
$env:FIREWALL_ENABLED = "false"
$env:EVENT_BUS_QUEUE_SIZE = "5000"
$env:SERVER_DISPLAY_IP = $serverIp
$env:GATEWAY_IP = $gatewayIp
$env:SCAN_SUBNET = $scanSubnet
$env:NETWORK_INTERFACE = ""
$env:COWRIE_LOG_PATH = ".\\cowrie\\logs\\cowrie.json"
$env:HTTP_HONEYPOT_HOST = "0.0.0.0"
$env:HTTP_HONEYPOT_PORT = "8888"

Set-Location $backendRoot
Write-Host "Starting host-native backend on http://127.0.0.1:8000"
Write-Host "Server display IP: $serverIp"
Write-Host "Gateway IP: $gatewayIp"
Write-Host "Scan subnet: $scanSubnet"
Write-Host "Cowrie log path: $env:COWRIE_LOG_PATH"

py -3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
