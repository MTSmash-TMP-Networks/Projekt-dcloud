@echo off
setlocal EnableExtensions

rem dcloud native Windows Python GitHub bootstrap installer for cmd.exe
rem Downloads the project archive from GitHub with curl and starts the Python installer.
rem This variant does not use Docker, WSL2 or virtualization.
rem If Python is missing, the local installer can install it automatically via winget or Chocolatey.
rem
rem Recommended one-liner in Windows CMD:
rem   curl.exe -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/Script/install_windows_python_from_github.cmd -o "%TEMP%\install_dcloud_windows_python.cmd" && cmd /c "%TEMP%\install_dcloud_windows_python.cmd"
rem
rem Optional environment variables before running:
rem   set DCLOUD_NODE_NAME=mein-windows-peer
rem   set DCLOUD_DASHBOARD_PORT=8787
rem   set DCLOUD_STORAGE_LIMIT_GB=200
rem   set DCLOUD_WINDOWS_APP_DIR=%LOCALAPPDATA%\dcloud\app
rem   set DCLOUD_WINDOWS_DATA_DIR=%LOCALAPPDATA%\dcloud\data
rem   set DCLOUD_AUTO_INSTALL_PYTHON=1
rem   set DCLOUD_PYTHON_WINGET_ID=Python.Python.3.12

if not defined DCLOUD_GITHUB_OWNER set "DCLOUD_GITHUB_OWNER=MTSmash-TMP-Networks"
if not defined DCLOUD_GITHUB_REPO set "DCLOUD_GITHUB_REPO=Projekt-dcloud"
if not defined DCLOUD_GITHUB_BRANCH set "DCLOUD_GITHUB_BRANCH=main"
if not defined DCLOUD_BOOTSTRAP_DIR set "DCLOUD_BOOTSTRAP_DIR=%TEMP%\dcloud-windows-python-github-install"
if not defined DCLOUD_WINDOWS_APP_DIR set "DCLOUD_WINDOWS_APP_DIR=%LOCALAPPDATA%\dcloud\app"
if not defined DCLOUD_WINDOWS_DATA_DIR set "DCLOUD_WINDOWS_DATA_DIR=%LOCALAPPDATA%\dcloud\data"

set "BOOTSTRAP_DIR=%DCLOUD_BOOTSTRAP_DIR%"
set "ARCHIVE_FILE=%BOOTSTRAP_DIR%\project.zip"
set "DOWNLOAD_URL=https://github.com/%DCLOUD_GITHUB_OWNER%/%DCLOUD_GITHUB_REPO%/archive/refs/heads/%DCLOUD_GITHUB_BRANCH%.zip"
set "REF_API_URL=https://api.github.com/repos/%DCLOUD_GITHUB_OWNER%/%DCLOUD_GITHUB_REPO%/git/ref/heads/%DCLOUD_GITHUB_BRANCH%"

where curl >nul 2>nul
if errorlevel 1 (
  echo [dcloud-python-bootstrap] ERROR: curl.exe was not found.
  echo Windows 10/11 normally includes curl. Please install curl or download the ZIP manually.
  exit /b 1
)

where powershell >nul 2>nul
if errorlevel 1 (
  echo [dcloud-python-bootstrap] ERROR: powershell.exe was not found.
  exit /b 1
)

if not defined DCLOUD_GIT_BRANCH set "DCLOUD_GIT_BRANCH=%DCLOUD_GITHUB_BRANCH%"
if not defined DCLOUD_GIT_REVISION (
  for /f "usebackq delims=" %%R in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $j=(Invoke-RestMethod -Uri '%REF_API_URL%' -UseBasicParsing); if ($j.object.sha) { $j.object.sha.Substring(0, [Math]::Min(12, $j.object.sha.Length)) } else { 'unbekannt' } } catch { 'unbekannt' }"`) do set "DCLOUD_GIT_REVISION=%%R"
)
if not defined DCLOUD_GIT_REVISION set "DCLOUD_GIT_REVISION=unbekannt"

echo [dcloud-python-bootstrap] GitHub revision: %DCLOUD_GIT_REVISION% (%DCLOUD_GIT_BRANCH%)
echo [dcloud-python-bootstrap] App directory: %DCLOUD_WINDOWS_APP_DIR%
echo [dcloud-python-bootstrap] Data directory: %DCLOUD_WINDOWS_DATA_DIR%

if exist "%BOOTSTRAP_DIR%" rmdir /s /q "%BOOTSTRAP_DIR%" 2>nul
mkdir "%BOOTSTRAP_DIR%" 2>nul
if errorlevel 1 (
  echo [dcloud-python-bootstrap] ERROR: Could not create bootstrap directory.
  exit /b 1
)

echo [dcloud-python-bootstrap] Downloading: %DOWNLOAD_URL%
curl.exe -fL "%DOWNLOAD_URL%" -o "%ARCHIVE_FILE%"
if errorlevel 1 (
  echo [dcloud-python-bootstrap] ERROR: GitHub archive download failed.
  exit /b 1
)

echo [dcloud-python-bootstrap] Extracting archive.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '%ARCHIVE_FILE%' -DestinationPath '%BOOTSTRAP_DIR%' -Force"
if errorlevel 1 (
  echo [dcloud-python-bootstrap] ERROR: Archive extraction failed.
  exit /b 1
)

set "PROJECT_DIR="
for /d %%D in ("%BOOTSTRAP_DIR%\*") do (
  if exist "%%~fD\requirements.txt" if exist "%%~fD\dcloud_client" set "PROJECT_DIR=%%~fD"
)

if not defined PROJECT_DIR (
  echo [dcloud-python-bootstrap] ERROR: The downloaded archive does not contain a valid dcloud project.
  exit /b 1
)

if not exist "%PROJECT_DIR%\Script\install_windows_python.cmd" (
  echo [dcloud-python-bootstrap] ERROR: Script\install_windows_python.cmd was not found in the GitHub archive.
  echo Please push the current project version to GitHub first.
  exit /b 1
)

if exist "%DCLOUD_WINDOWS_APP_DIR%\Script\install_windows_python.cmd" (
  echo [dcloud-python-bootstrap] Stopping existing native Python installation if it is running.
  call "%DCLOUD_WINDOWS_APP_DIR%\Script\install_windows_python.cmd" -Stop >nul 2>nul
)
if exist "%DCLOUD_WINDOWS_APP_DIR%" rmdir /s /q "%DCLOUD_WINDOWS_APP_DIR%" 2>nul
mkdir "%DCLOUD_WINDOWS_APP_DIR%" 2>nul
if errorlevel 1 (
  echo [dcloud-python-bootstrap] ERROR: Could not create app directory.
  exit /b 1
)

echo [dcloud-python-bootstrap] Copying project files.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Copy-Item -Path '%PROJECT_DIR%\*' -Destination '%DCLOUD_WINDOWS_APP_DIR%' -Recurse -Force"
if errorlevel 1 (
  echo [dcloud-python-bootstrap] ERROR: Could not copy project files.
  exit /b 1
)

> "%DCLOUD_WINDOWS_APP_DIR%\.dcloud_git_revision" echo %DCLOUD_GIT_REVISION%
> "%DCLOUD_WINDOWS_APP_DIR%\.dcloud_git_branch" echo %DCLOUD_GIT_BRANCH%
> "%DCLOUD_WINDOWS_APP_DIR%\.dcloud_windows_data_dir" echo %DCLOUD_WINDOWS_DATA_DIR%

if not exist "%DCLOUD_WINDOWS_APP_DIR%\Script\install_windows_python.cmd" (
  echo [dcloud-python-bootstrap] ERROR: Copied installer was not found.
  exit /b 1
)

echo [dcloud-python-bootstrap] Starting native Windows Python installation.
call "%DCLOUD_WINDOWS_APP_DIR%\Script\install_windows_python.cmd" %*
exit /b %ERRORLEVEL%
