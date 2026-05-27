@echo off
setlocal EnableExtensions

rem dcloud Windows Docker installer/launcher for CMD
rem Uses the existing PowerShell Docker helper, but can be started from cmd.exe.
rem
rem Local usage from the unpacked project:
rem   Script\install_windows_docker.cmd
rem
rem Optional environment variables:
rem   set DCLOUD_NODE_NAME=mein-windows-peer
rem   set DCLOUD_DASHBOARD_PORT=8787
rem   set DCLOUD_DISCOVERY_UDP_PORT=6881
rem   set DCLOUD_STORAGE_LIMIT_GB=200
rem   Script\install_windows_docker.cmd
rem
rem Management examples:
rem   Script\install_windows_docker.cmd -Logs
rem   Script\install_windows_docker.cmd -Restart
rem   Script\install_windows_docker.cmd -Stop

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "REPO_ROOT=%%~fI"
set "PS_SCRIPT=%REPO_ROOT%\scripts\install_dcloud_docker_windows.ps1"

if not exist "%PS_SCRIPT%" (
  echo [dcloud-windows-docker] ERROR: PowerShell helper was not found:
  echo %PS_SCRIPT%
  exit /b 1
)

where docker >nul 2>nul
if errorlevel 1 (
  echo [dcloud-windows-docker] ERROR: Docker was not found.
  echo Please install and start Docker Desktop, then run this script again.
  exit /b 1
)

where powershell >nul 2>nul
if errorlevel 1 (
  echo [dcloud-windows-docker] ERROR: powershell.exe was not found.
  exit /b 1
)

if not defined DCLOUD_NODE_NAME set "DCLOUD_NODE_NAME=dcloud-windows-docker"
if not defined DCLOUD_DASHBOARD_PORT set "DCLOUD_DASHBOARD_PORT=8787"
if not defined DCLOUD_DISCOVERY_UDP_PORT set "DCLOUD_DISCOVERY_UDP_PORT=6881"
if not defined DCLOUD_STORAGE_LIMIT_GB set "DCLOUD_STORAGE_LIMIT_GB=50"

pushd "%REPO_ROOT%" >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -NodeName "%DCLOUD_NODE_NAME%" -DashboardPort %DCLOUD_DASHBOARD_PORT% -DiscoveryUdpPort %DCLOUD_DISCOVERY_UDP_PORT% -StorageLimitGiB %DCLOUD_STORAGE_LIMIT_GB% %*
set "EXIT_CODE=%ERRORLEVEL%"
popd >nul

exit /b %EXIT_CODE%
