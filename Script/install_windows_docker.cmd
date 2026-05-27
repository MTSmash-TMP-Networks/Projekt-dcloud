@echo off
setlocal EnableExtensions

rem dcloud Windows Docker installer/launcher for CMD
rem Uses the existing PowerShell Docker helper, but can be started from cmd.exe.
rem If Docker Desktop is missing, this script can install Chocolatey and Docker Desktop automatically.
rem
rem Local usage from the unpacked project:
rem   Script\install_windows_docker.cmd
rem
rem Optional environment variables:
rem   set DCLOUD_NODE_NAME=mein-windows-peer
rem   set DCLOUD_DASHBOARD_PORT=8787
rem   set DCLOUD_DISCOVERY_UDP_PORT=6881
rem   set DCLOUD_STORAGE_LIMIT_GB=200
rem   set DCLOUD_AUTO_INSTALL_DOCKER=1      rem default: 1, install Docker Desktop via Chocolatey if missing
rem   set DCLOUD_AUTO_START_DOCKER=1        rem default: 1, start Docker Desktop if the engine is not running
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

where powershell >nul 2>nul
if errorlevel 1 (
  echo [dcloud-windows-docker] ERROR: powershell.exe was not found.
  exit /b 1
)

if not defined DCLOUD_AUTO_INSTALL_DOCKER set "DCLOUD_AUTO_INSTALL_DOCKER=1"
if not defined DCLOUD_AUTO_START_DOCKER set "DCLOUD_AUTO_START_DOCKER=1"

call :ensure_docker_available
if errorlevel 1 exit /b 1

if not defined DCLOUD_NODE_NAME set "DCLOUD_NODE_NAME=dcloud-windows-docker"
if not defined DCLOUD_DASHBOARD_PORT set "DCLOUD_DASHBOARD_PORT=8787"
if not defined DCLOUD_DISCOVERY_UDP_PORT set "DCLOUD_DISCOVERY_UDP_PORT=6881"
if not defined DCLOUD_STORAGE_LIMIT_GB set "DCLOUD_STORAGE_LIMIT_GB=50"

pushd "%REPO_ROOT%" >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -NodeName "%DCLOUD_NODE_NAME%" -DashboardPort %DCLOUD_DASHBOARD_PORT% -DiscoveryUdpPort %DCLOUD_DISCOVERY_UDP_PORT% -StorageLimitGiB %DCLOUD_STORAGE_LIMIT_GB% %*
set "EXIT_CODE=%ERRORLEVEL%"
popd >nul

exit /b %EXIT_CODE%

:ensure_docker_available
call :add_known_paths
where docker >nul 2>nul
if not errorlevel 1 (
  call :ensure_docker_engine_running
  exit /b %ERRORLEVEL%
)

if /I "%DCLOUD_AUTO_INSTALL_DOCKER%"=="0" (
  echo [dcloud-windows-docker] ERROR: Docker was not found.
  echo Install Docker Desktop manually or set DCLOUD_AUTO_INSTALL_DOCKER=1.
  exit /b 1
)

call :require_admin_for_install
if errorlevel 1 exit /b 1

call :ensure_chocolatey
if errorlevel 1 exit /b 1

call :install_docker_desktop
if errorlevel 1 exit /b 1

call :add_known_paths
where docker >nul 2>nul
if errorlevel 1 (
  echo [dcloud-windows-docker] Docker Desktop was installed, but docker.exe is not visible in this CMD session yet.
  echo Please close this window, open a new CMD window, and run the command again.
  echo If Windows asks for a restart, restart Windows first.
  exit /b 1
)

call :ensure_docker_engine_running
exit /b %ERRORLEVEL%

:require_admin_for_install
net session >nul 2>nul
if not errorlevel 1 exit /b 0
echo [dcloud-windows-docker] Docker Desktop is missing and automatic installation needs Administrator rights.
echo Please open CMD as Administrator and run the command again.
echo To disable automatic Docker installation, run: set DCLOUD_AUTO_INSTALL_DOCKER=0
exit /b 1

:ensure_chocolatey
where choco >nul 2>nul
if not errorlevel 1 exit /b 0

if exist "%ProgramData%\chocolatey\bin\choco.exe" (
  set "PATH=%ProgramData%\chocolatey\bin;%PATH%"
  exit /b 0
)

echo [dcloud-windows-docker] Chocolatey was not found. Installing Chocolatey...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
if errorlevel 1 (
  echo [dcloud-windows-docker] ERROR: Chocolatey installation failed.
  exit /b 1
)
set "PATH=%ProgramData%\chocolatey\bin;%PATH%"
where choco >nul 2>nul
if errorlevel 1 (
  echo [dcloud-windows-docker] ERROR: Chocolatey was installed, but choco.exe is not available yet.
  echo Please open a new Administrator CMD window and run the command again.
  exit /b 1
)
exit /b 0

:install_docker_desktop
echo [dcloud-windows-docker] Installing Docker Desktop with Chocolatey...
choco install docker-desktop -y --no-progress
if errorlevel 1 (
  echo [dcloud-windows-docker] ERROR: Docker Desktop installation via Chocolatey failed.
  exit /b 1
)
exit /b 0

:add_known_paths
if exist "%ProgramData%\chocolatey\bin" set "PATH=%ProgramData%\chocolatey\bin;%PATH%"
if exist "%ProgramFiles%\Docker\Docker\resources\bin" set "PATH=%ProgramFiles%\Docker\Docker\resources\bin;%PATH%"
exit /b 0

:ensure_docker_engine_running
where docker >nul 2>nul
if errorlevel 1 (
  echo [dcloud-windows-docker] ERROR: docker.exe was not found.
  exit /b 1
)

docker version >nul 2>nul
if not errorlevel 1 exit /b 0

if /I "%DCLOUD_AUTO_START_DOCKER%"=="0" (
  echo [dcloud-windows-docker] ERROR: Docker Desktop is installed, but the Docker engine is not running.
  echo Please start Docker Desktop and run the command again.
  exit /b 1
)

call :start_docker_desktop
if errorlevel 1 exit /b 1

set /a DCLOUD_WAIT_SECONDS=0
:wait_for_docker_engine
docker version >nul 2>nul
if not errorlevel 1 exit /b 0
if %DCLOUD_WAIT_SECONDS% GEQ 300 goto :docker_engine_timeout
echo [dcloud-windows-docker] Waiting for Docker Desktop engine... %DCLOUD_WAIT_SECONDS%s
timeout /t 5 /nobreak >nul
set /a DCLOUD_WAIT_SECONDS+=5
goto :wait_for_docker_engine

:docker_engine_timeout
echo [dcloud-windows-docker] ERROR: Docker Desktop did not become ready within 5 minutes.
echo If Docker Desktop was just installed, Windows may need a restart or WSL2 setup may need to finish.
echo Start Docker Desktop manually, wait until it says it is running, then run this command again.
exit /b 1

:start_docker_desktop
if exist "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" (
  echo [dcloud-windows-docker] Starting Docker Desktop...
  start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
  exit /b 0
)
if exist "%LocalAppData%\Docker\Docker Desktop.exe" (
  echo [dcloud-windows-docker] Starting Docker Desktop...
  start "" "%LocalAppData%\Docker\Docker Desktop.exe"
  exit /b 0
)
echo [dcloud-windows-docker] ERROR: Docker Desktop is installed, but Docker Desktop.exe was not found.
echo Please start Docker Desktop manually and run this command again.
exit /b 1
