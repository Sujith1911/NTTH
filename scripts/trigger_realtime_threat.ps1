param(
    [string]$Scenario = "port_scan",
    [int]$Count = 25,
    [double]$DelayMs = 5,
    [string]$Username = "admin",
    [string]$Password = "changeme"
)

$ErrorActionPreference = "Stop"

$baseUrl = "http://127.0.0.1:8000/api/v1"

$loginBody = @{
    username = $Username
    password = $Password
} | ConvertTo-Json

$login = Invoke-RestMethod -Method Post -Uri "$baseUrl/auth/login" -ContentType "application/json" -Body $loginBody
$token = $login.access_token

$headers = @{
    Authorization = "Bearer $token"
}

$body = @{
    scenario = $Scenario
    count = $Count
    delay_ms = $DelayMs
} | ConvertTo-Json

$response = Invoke-RestMethod -Method Post -Uri "$baseUrl/system/simulate-threat" -Headers $headers -ContentType "application/json" -Body $body
$response | ConvertTo-Json -Depth 4
