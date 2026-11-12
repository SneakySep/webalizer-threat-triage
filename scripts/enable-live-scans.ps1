<#
.SYNOPSIS
    Recreates the Webalizer triage stack with the VirusTotal key from .env
    and validates the key before the first real scan.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$EnvPath = Join-Path $RepoRoot '.env'
$ExamplePath = Join-Path $RepoRoot '.env.example'

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Fail {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "ERROR: $Message" -ForegroundColor Red
}

function Get-EnvValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$Default = ''
    )

    if (-not (Test-Path -LiteralPath $EnvPath)) {
        return $Default
    }

    $pattern = "^\s*$([regex]::Escape($Name))\s*="
    $line = Get-Content -LiteralPath $EnvPath -Encoding UTF8 |
        Where-Object { $_ -match $pattern } |
        Select-Object -First 1

    if (-not $line) {
        return $Default
    }

    $value = ($line -replace $pattern, '').Trim()
    if ($value.Length -ge 2) {
        $first = $value.Substring(0, 1)
        $last = $value.Substring($value.Length - 1, 1)
        $quoted = (($first -eq '"') -and ($last -eq '"')) -or (($first -eq "'") -and ($last -eq "'"))
        if ($quoted) {
            $value = $value.Substring(1, $value.Length - 2).Trim()
        }
    }
    return $value
}

Write-Step 'Checking .env configuration'

if (-not (Test-Path -LiteralPath $EnvPath)) {
    Copy-Item -LiteralPath $ExamplePath -Destination $EnvPath
    Write-Fail '.env did not exist and was created from .env.example.'
    Write-Host 'Paste your VirusTotal key into VT_API_KEY in .env, then run this script again.'
    exit 1
}

$VtApiKey = Get-EnvValue -Name 'VT_API_KEY'
if ([string]::IsNullOrWhiteSpace($VtApiKey)) {
    Write-Fail 'VT_API_KEY is empty or missing in .env.'
    Write-Host 'Paste your VirusTotal key after VT_API_KEY= in .env, then run this script again.'
    exit 1
}
Write-Host 'VT_API_KEY is configured (value hidden).' -ForegroundColor Green

$ApiPort = Get-EnvValue -Name 'API_PORT' -Default '8000'
if ([string]::IsNullOrWhiteSpace($ApiPort)) {
    $ApiPort = '8000'
}

Write-Step 'Checking Docker Compose'
try {
    & docker compose version *> $null
} catch {
    Write-Fail 'Docker is not installed or is not on PATH.'
    exit 1
}
if ($LASTEXITCODE -ne 0) {
    Write-Fail 'Docker Compose is not available.'
    exit 1
}

if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    Write-Fail 'curl.exe is required to poll the readiness endpoint.'
    exit 1
}

Write-Step 'Rebuilding and recreating the API and worker with the new environment'
& docker compose up -d --build --force-recreate worker api
if ($LASTEXITCODE -ne 0) {
    Write-Fail 'docker compose up failed. Review the output above.'
    exit 1
}

Write-Step 'Waiting for the API to become ready'
$ReadyUrl = "http://localhost:$ApiPort/health/ready"
$Ready = $false
for ($Attempt = 1; $Attempt -le 60; $Attempt++) {
    $StatusCode = (& curl.exe -s -o NUL --max-time 5 -w '%{http_code}' $ReadyUrl)
    if ($StatusCode -eq '200') {
        $Ready = $true
        break
    }
    Start-Sleep -Seconds 2
}

if (-not $Ready) {
    Write-Fail 'The API did not become ready within 120 seconds.'
    & docker compose logs --tail=50 api worker
    exit 1
}
Write-Host 'API and worker are ready.' -ForegroundColor Green

Write-Step 'Validating the VirusTotal key'
& docker compose exec -T worker python -m scripts.verify_vt_key
if ($LASTEXITCODE -ne 0) {
    Write-Fail 'The VirusTotal preflight failed. See the message above.'
    exit 1
}

Write-Host ''
Write-Host 'Live scans are enabled.' -ForegroundColor Green
Write-Host "API docs: http://localhost:$ApiPort/docs"
Write-Host ''
$ScanUrl = "http://localhost:$ApiPort/api/v1/triage/scan"
Write-Host 'Submit a first scan from PowerShell:'
Write-Host '$body = @{ target = ''example.com'' } | ConvertTo-Json'
Write-Host "Invoke-RestMethod -Method Post -Uri '$ScanUrl' -ContentType 'application/json' -Body `$body"
