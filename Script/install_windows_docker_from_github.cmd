@echo off
setlocal EnableExtensions

rem dcloud Windows Docker GitHub bootstrap installer for cmd.exe
rem Downloads the project archive from GitHub with curl and starts Docker installation.
rem
rem Recommended one-liner in Windows CMD:
rem   curl.exe -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/Script/install_windows_docker_from_github.cmd -o "%TEMP%\install_dcloud_windows_docker.cmd" && cmd /c "%TEMP%\install_dcloud_windows_docker.cmd"
rem
rem Optional environment variables before running:
rem   set DCLOUD_NODE_NAME=mein-windows-peer
rem   set DCLOUD_DASHBOARD_PORT=8787
rem   set DCLOUD_STORAGE_LIMIT_GB=200

if not defined DCLOUD_GITHUB_OWNER set "DCLOUD_GITHUB_OWNER=MTSmash-TMP-Networks"
if not defined DCLOUD_GITHUB_REPO set "DCLOUD_GITHUB_REPO=Projekt-dcloud"
if not defined DCLOUD_GITHUB_BRANCH set "DCLOUD_GITHUB_BRANCH=main"
if not defined DCLOUD_BOOTSTRAP_DIR set "DCLOUD_BOOTSTRAP_DIR=%TEMP%\dcloud-windows-github-install"

set "BOOTSTRAP_DIR=%DCLOUD_BOOTSTRAP_DIR%"
set "ARCHIVE_FILE=%BOOTSTRAP_DIR%\project.zip"
set "DOWNLOAD_URL=https://github.com/%DCLOUD_GITHUB_OWNER%/%DCLOUD_GITHUB_REPO%/archive/refs/heads/%DCLOUD_GITHUB_BRANCH%.zip"
set "REF_API_URL=https://api.github.com/repos/%DCLOUD_GITHUB_OWNER%/%DCLOUD_GITHUB_REPO%/git/ref/heads/%DCLOUD_GITHUB_BRANCH%"

echo [dcloud-github-bootstrap] Bootstrap directory: %BOOTSTRAP_DIR%

where curl >nul 2>nul
if errorlevel 1 (
  echo [dcloud-github-bootstrap] ERROR: curl.exe was not found.
  echo Windows 10/11 normally includes curl. Please install curl or download the ZIP manually.
  exit /b 1
)

where powershell >nul 2>nul
if errorlevel 1 (
  echo [dcloud-github-bootstrap] ERROR: powershell.exe was not found.
  exit /b 1
)

where docker >nul 2>nul
if errorlevel 1 (
  echo [dcloud-github-bootstrap] ERROR: Docker was not found.
  echo Please install and start Docker Desktop, then run this command again.
  exit /b 1
)

if not defined DCLOUD_GIT_BRANCH set "DCLOUD_GIT_BRANCH=%DCLOUD_GITHUB_BRANCH%"
if not defined DCLOUD_GIT_REVISION (
  for /f "usebackq delims=" %%R in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $j=(Invoke-RestMethod -Uri '%REF_API_URL%' -UseBasicParsing); if ($j.object.sha) { $j.object.sha.Substring(0, [Math]::Min(12, $j.object.sha.Length)) } else { 'unbekannt' } } catch { 'unbekannt' }"`) do set "DCLOUD_GIT_REVISION=%%R"
)
if not defined DCLOUD_GIT_REVISION set "DCLOUD_GIT_REVISION=unbekannt"
echo [dcloud-github-bootstrap] GitHub revision: %DCLOUD_GIT_REVISION% (%DCLOUD_GIT_BRANCH%)

if exist "%BOOTSTRAP_DIR%" rmdir /s /q "%BOOTSTRAP_DIR%" 2>nul
mkdir "%BOOTSTRAP_DIR%" 2>nul
if errorlevel 1 (
  echo [dcloud-github-bootstrap] ERROR: Could not create bootstrap directory.
  exit /b 1
)

echo [dcloud-github-bootstrap] Downloading: %DOWNLOAD_URL%
curl.exe -fL "%DOWNLOAD_URL%" -o "%ARCHIVE_FILE%"
if errorlevel 1 (
  echo [dcloud-github-bootstrap] ERROR: GitHub archive download failed.
  exit /b 1
)

echo [dcloud-github-bootstrap] Extracting archive.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '%ARCHIVE_FILE%' -DestinationPath '%BOOTSTRAP_DIR%' -Force"
if errorlevel 1 (
  echo [dcloud-github-bootstrap] ERROR: Archive extraction failed.
  exit /b 1
)

set "PROJECT_DIR="
for /d %%D in ("%BOOTSTRAP_DIR%\*") do (
  if exist "%%~fD\requirements.txt" if exist "%%~fD\dcloud_client" set "PROJECT_DIR=%%~fD"
)

if not defined PROJECT_DIR (
  echo [dcloud-github-bootstrap] ERROR: The downloaded archive does not contain a valid dcloud project.
  exit /b 1
)

if not exist "%PROJECT_DIR%\Script\install_windows_docker.cmd" (
  echo [dcloud-github-bootstrap] ERROR: Script\install_windows_docker.cmd was not found in the GitHub archive.
  echo Please push the current project version to GitHub first.
  exit /b 1
)

> "%PROJECT_DIR%\.dcloud_git_revision" echo %DCLOUD_GIT_REVISION%
> "%PROJECT_DIR%\.dcloud_git_branch" echo %DCLOUD_GIT_BRANCH%

echo [dcloud-github-bootstrap] Starting Windows Docker installation from: %PROJECT_DIR%
call "%PROJECT_DIR%\Script\install_windows_docker.cmd" %*
exit /b %ERRORLEVEL%
