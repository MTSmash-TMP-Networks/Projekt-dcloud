<#
.SYNOPSIS
  Starts dcloud on Windows through Docker Desktop.

.DESCRIPTION
  This script avoids the fragile native Windows Python/service setup. It builds and
  starts the local dcloud Docker container, creates a persistent docker-data folder
  and writes docker/.env.windows for Compose.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1 -NodeName "Mein dcloud" -StorageLimitGiB 200 -DashboardPort 8787

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1 -Logs
#>
[CmdletBinding()]
param(
    [string]$NodeName = "dcloud-windows-docker",
    [ValidateRange(1024, 65535)]
    [int]$DashboardPort = 8787,
    [ValidateRange(1024, 65535)]
    [int]$DiscoveryUdpPort = 6881,
    [ValidateRange(1, 1048576)]
    [int]$StorageLimitGiB = 50,
    [switch]$EnableSmb,
    [ValidateRange(1, 65535)]
    [int]$SmbPort = 445,
    [switch]$NoBuild,
    [switch]$Restart,
    [switch]$Stop,
    [switch]$Logs,
    [switch]$Status,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "[dcloud-docker] $Message" -ForegroundColor Cyan
}

function Fail {
    param([string]$Message)
    Write-Host "[dcloud-docker] FEHLER: $Message" -ForegroundColor Red
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..")
Set-Location $RepoRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail "Docker wurde nicht gefunden. Bitte Docker Desktop installieren und danach dieses Skript erneut starten."
}

try {
    docker version | Out-Null
} catch {
    Fail "Docker antwortet nicht. Bitte Docker Desktop starten und warten, bis die Engine bereit ist."
}

function Get-DcloudGitRevision {
    if ($env:DCLOUD_GIT_REVISION -and $env:DCLOUD_GIT_REVISION -ne "unbekannt") { return $env:DCLOUD_GIT_REVISION }
    $marker = Join-Path $RepoRoot ".dcloud_git_revision"
    if (Test-Path $marker) {
        $value = (Get-Content -Path $marker -TotalCount 1 -ErrorAction SilentlyContinue).Trim()
        if ($value -and $value -ne "unbekannt") { return $value }
    }
    if ((Get-Command git -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $RepoRoot ".git"))) {
        $value = (& git -C $RepoRoot rev-parse --short=12 HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $value) { return $value.Trim() }
    }
    return "unbekannt"
}

function Get-DcloudGitBranch {
    if ($env:DCLOUD_GIT_BRANCH) { return $env:DCLOUD_GIT_BRANCH }
    $marker = Join-Path $RepoRoot ".dcloud_git_branch"
    if (Test-Path $marker) {
        $value = (Get-Content -Path $marker -TotalCount 1 -ErrorAction SilentlyContinue).Trim()
        if ($value) { return $value }
    }
    if ((Get-Command git -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $RepoRoot ".git"))) {
        $value = (& git -C $RepoRoot rev-parse --abbrev-ref HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $value) { return $value.Trim() }
    }
    return "main"
}

$DcloudGitRevision = Get-DcloudGitRevision
$DcloudGitBranch = Get-DcloudGitBranch

$DockerDir = Join-Path $RepoRoot "docker"
$DataDir = Join-Path $RepoRoot "docker-data"
$EnvFile = Join-Path $DockerDir ".env.windows"
New-Item -ItemType Directory -Force -Path $DockerDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

$IsControlCommand = $Stop -or $Restart -or $Logs -or $Status -or $Clean
if ((-not $IsControlCommand) -or (-not (Test-Path $EnvFile))) {
    $envContent = @"
DCLOUD_NODE_NAME=$NodeName
DCLOUD_DASHBOARD_PORT=$DashboardPort
DCLOUD_DISCOVERY_UDP_PORT=$DiscoveryUdpPort
DCLOUD_STORAGE_LIMIT_GB=$StorageLimitGiB
DCLOUD_SMB_PORT=$SmbPort
DCLOUD_GIT_REVISION=$DcloudGitRevision
DCLOUD_GIT_BRANCH=$DcloudGitBranch
"@
    Set-Content -Path $EnvFile -Value $envContent -Encoding UTF8
}

$composeArgs = @("compose", "--env-file", $EnvFile, "-f", "docker-compose.windows.yml")
if ($EnableSmb) {
    $composeArgs += @("-f", "docker-compose.smb.yml")
}

function Invoke-DockerCompose {
    param([string[]]$ArgsToAppend)
    & docker @composeArgs @ArgsToAppend
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose ist mit Exitcode $LASTEXITCODE fehlgeschlagen."
    }
}

if ($Clean) {
    Write-Step "Stoppe Container und entferne Container/Netzwerk. Persistente Daten bleiben in docker-data erhalten."
    Invoke-DockerCompose @("down")
    exit 0
}

if ($Stop) {
    Write-Step "Stoppe dcloud Docker-Container."
    Invoke-DockerCompose @("down")
    exit 0
}

if ($Restart) {
    Write-Step "Starte dcloud Docker-Container neu."
    Invoke-DockerCompose @("restart")
    exit 0
}

if ($Logs) {
    Write-Step "Zeige Live-Logs. Abbrechen mit Strg+C."
    Invoke-DockerCompose @("logs", "-f", "--tail", "200")
    exit 0
}

if ($Status) {
    Write-Step "Container-Status:"
    Invoke-DockerCompose @("ps")
    exit 0
}

try {
    if ($NoBuild) {
        Write-Step "Starte dcloud ohne neues Image zu bauen."
        Invoke-DockerCompose @("up", "-d")
    } else {
        Write-Step "Baue und starte dcloud Docker-Container."
        Invoke-DockerCompose @("up", "-d", "--build")
    }
} catch {
    Fail $_.Exception.Message
}

Write-Host ""
Write-Host "dcloud läuft jetzt in Docker." -ForegroundColor Green
Write-Host "Dashboard: http://127.0.0.1:$DashboardPort"
Write-Host "Datenordner: $DataDir"
Write-Host "Logs:      powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1 -Logs"
Write-Host "Stoppen:   powershell -ExecutionPolicy Bypass -File .\scripts\install_dcloud_docker_windows.ps1 -Stop"

if ($EnableSmb) {
    Write-Host ""
    Write-Host "Hinweis: SMB in Docker nutzt intern Port 445. Auf Windows ist Port 445 oft bereits durch Windows-Dateifreigabe belegt." -ForegroundColor Yellow
    Write-Host "Wenn der Container nicht startet, bitte ohne -EnableSmb starten oder Windows-Dateifreigabe/Portbelegung prüfen." -ForegroundColor Yellow
}
