<#
.SYNOPSIS
    ApexShield PowerShell Attack & Telemetry Generator (Windows Native)
.DESCRIPTION
    Executes high-velocity authentication bursts, headers inspection, and firewall checks.
#>

param (
    [string]$BaseUrl = "http://127.0.0.1:8000",
    [string]$TargetUser = "sarah.connor",
    [string]$Mode = "malware-burst" # "friction", "malware-burst", "sqli", "portscan"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " APEXSHIELD CYBER DEFENSE - POWERSHELL SIMULATOR " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

if ($Mode -eq "malware-burst") {
    Write-Host "[!] Launching High-Velocity Scripted Brute Force on user: $TargetUser" -ForegroundColor Red
    $endpoint = "$BaseUrl/api/v1/auth/login"
    
    1..7 | ForEach-Object {
        $attemptNum = $_
        $body = @{
            username = $TargetUser
            password = "WrongPassword_Attempt_$attemptNum"
        } | ConvertTo-Json

        $headers = @{
            "Content-Type" = "application/json"
            "User-Agent" = "PowerShell-Threat-Bot/2.1 (Windows NT 10.0)"
            "X-Forwarded-For" = "10.45.99.12"
        }

        try {
            $resp = Invoke-RestMethod -Uri $endpoint -Method Post -Body $body -Headers $headers -ErrorAction Stop
            Write-Host "Attempt $attemptNum : Unexpected Success" -ForegroundColor Yellow
        } catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            Write-Host "Attempt $attemptNum [HTTP $statusCode] -> Intercepted by ApexShield Detection Engine" -ForegroundColor DarkYellow
        }
        Start-Sleep -Milliseconds 100
    }
    
    Write-Host "`n[+] Checking SOC Active Incidents..." -ForegroundColor Cyan
    $incidents = Invoke-RestMethod -Uri "$BaseUrl/api/v1/soc/incidents" -Method Get
    $targetInc = $incidents | Where-Object { $_.username -eq $TargetUser } | Select-Object -First 1
    if ($targetInc) {
        Write-Host "[ALERT] Incident Confirmed: $($targetInc.incident_number)" -ForegroundColor Red
        Write-Host "        Title: $($targetInc.title)" -ForegroundColor White
        Write-Host "        Severity: $($targetInc.severity) | Risk Score: $($targetInc.risk_score)/100" -ForegroundColor Red
        Write-Host "        MITRE Technique: $($targetInc.mitre_technique)" -ForegroundColor Yellow
    }
}
elseif ($Mode -eq "friction") {
    Write-Host "[+] Simulating Human User Friction for: $TargetUser" -ForegroundColor Green
    $resp = Invoke-RestMethod -Uri "$BaseUrl/api/v1/simulate/human-login-friction?target_user=$TargetUser" -Method Post
    Write-Host "Result: $($resp.summary)" -ForegroundColor White
}
