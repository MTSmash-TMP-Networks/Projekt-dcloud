@echo off
setlocal EnableExtensions

rem dcloud native Windows Python installer/launcher for cmd.exe
rem This variant does not use Docker, WSL2 or virtualization.
rem If Python is missing, this script can install it automatically via winget or Chocolatey.
rem
rem Local usage from the unpacked project:
rem   Script\install_windows_python.cmd
rem
rem Optional environment variables:
rem   set DCLOUD_NODE_NAME=mein-windows-peer
rem   set DCLOUD_DASHBOARD_PORT=8787
rem   set DCLOUD_DISCOVERY_UDP_PORT=6881
rem   set DCLOUD_STORAGE_LIMIT_GB=200
rem   set DCLOUD_WINDOWS_DATA_DIR=C:\dcloud-data
rem   set DCLOUD_ENABLE_SMB=0
rem   set DCLOUD_ADD_FIREWALL_RULE=1
rem   set DCLOUD_AUTO_INSTALL_PYTHON=1   rem default: 1, install Python automatically if missing
rem   set DCLOUD_PYTHON_WINGET_ID=Python.Python.3.12
rem
rem Management examples:
rem   Script\install_windows_python.cmd -Logs
rem   Script\install_windows_python.cmd -Restart
rem   Script\install_windows_python.cmd -Stop
rem   Script\install_windows_python.cmd -Status
rem   Script\install_windows_python.cmd -Run

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "REPO_ROOT=%%~fI"
set "DATA_MARKER=%REPO_ROOT%\.dcloud_windows_data_dir"

if not defined DCLOUD_WINDOWS_DATA_DIR if exist "%DATA_MARKER%" set /p DCLOUD_WINDOWS_DATA_DIR=<"%DATA_MARKER%"
if not defined DCLOUD_WINDOWS_DATA_DIR set "DCLOUD_WINDOWS_DATA_DIR=%REPO_ROOT%\windows-data"
if not defined DCLOUD_DASHBOARD_PORT set "DCLOUD_DASHBOARD_PORT=8787"
if not defined DCLOUD_DISCOVERY_UDP_PORT set "DCLOUD_DISCOVERY_UDP_PORT=6881"
if not defined DCLOUD_STORAGE_LIMIT_GB set "DCLOUD_STORAGE_LIMIT_GB=50"
if not defined DCLOUD_ENABLE_SMB set "DCLOUD_ENABLE_SMB=0"
if not defined DCLOUD_ADD_FIREWALL_RULE set "DCLOUD_ADD_FIREWALL_RULE=1"
if not defined DCLOUD_AUTO_INSTALL_PYTHON set "DCLOUD_AUTO_INSTALL_PYTHON=1"
if not defined DCLOUD_PYTHON_WINGET_ID set "DCLOUD_PYTHON_WINGET_ID=Python.Python.3.12"

set "VENV_DIR=%REPO_ROOT%\.venv"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "CONFIG_FILE=%DCLOUD_WINDOWS_DATA_DIR%\config.yml"
set "LOG_DIR=%DCLOUD_WINDOWS_DATA_DIR%\logs"
set "LOG_FILE=%LOG_DIR%\dcloud.log"
set "ERR_FILE=%LOG_DIR%\dcloud.err.log"
set "PID_FILE=%DCLOUD_WINDOWS_DATA_DIR%\dcloud.pid"
set "CONFIG_HELPER=%REPO_ROOT%\scripts\configure_dcloud_windows_python.py"

set "COMMAND=install"
if /I "%~1"=="-Stop" set "COMMAND=stop"
if /I "%~1"=="/Stop" set "COMMAND=stop"
if /I "%~1"=="-Restart" set "COMMAND=restart"
if /I "%~1"=="/Restart" set "COMMAND=restart"
if /I "%~1"=="-Logs" set "COMMAND=logs"
if /I "%~1"=="/Logs" set "COMMAND=logs"
if /I "%~1"=="-Status" set "COMMAND=status"
if /I "%~1"=="/Status" set "COMMAND=status"
if /I "%~1"=="-Run" set "COMMAND=run"
if /I "%~1"=="/Run" set "COMMAND=run"
if /I "%~1"=="-InstallOnly" set "COMMAND=installonly"
if /I "%~1"=="/InstallOnly" set "COMMAND=installonly"

if "%COMMAND%"=="stop" goto :stop_service
if "%COMMAND%"=="logs" goto :show_logs
if "%COMMAND%"=="status" goto :show_status
if "%COMMAND%"=="restart" goto :restart_service

call :install_python_app
if errorlevel 1 exit /b 1

if "%COMMAND%"=="installonly" (
  echo [dcloud-windows-python] Installation complete. Start later with: Script\install_windows_python.cmd
  exit /b 0
)

if "%COMMAND%"=="run" goto :run_foreground

goto :start_service

:install_python_app
echo [dcloud-windows-python] Repository: %REPO_ROOT%
echo [dcloud-windows-python] Data directory: %DCLOUD_WINDOWS_DATA_DIR%

if not exist "%REPO_ROOT%\requirements.txt" (
  echo [dcloud-windows-python] ERROR: requirements.txt was not found.
  exit /b 1
)
if not exist "%CONFIG_HELPER%" (
  echo [dcloud-windows-python] ERROR: configure helper was not found:
  echo %CONFIG_HELPER%
  exit /b 1
)

call :find_python
if errorlevel 1 exit /b 1

if not exist "%VENV_PYTHON%" (
  echo [dcloud-windows-python] Creating Python virtual environment.
  "%PYTHON_EXE%" -m venv "%VENV_DIR%"
  if errorlevel 1 (
    echo [dcloud-windows-python] ERROR: Could not create virtual environment.
    echo Please install Python with the venv module and try again.
    exit /b 1
  )
)

if not exist "%VENV_PYTHON%" (
  echo [dcloud-windows-python] ERROR: venv python was not created.
  exit /b 1
)

mkdir "%LOG_DIR%" 2>nul
> "%DATA_MARKER%" echo %DCLOUD_WINDOWS_DATA_DIR%

echo [dcloud-windows-python] Installing/updating Python packages.
"%VENV_PYTHON%" -m pip install --upgrade pip setuptools wheel
if errorlevel 1 exit /b 1
"%VENV_PYTHON%" -m pip install -r "%REPO_ROOT%\requirements.txt"
if errorlevel 1 exit /b 1

if exist "%REPO_ROOT%\.dcloud_git_revision" if not defined DCLOUD_GIT_REVISION set /p DCLOUD_GIT_REVISION=<"%REPO_ROOT%\.dcloud_git_revision"
if exist "%REPO_ROOT%\.dcloud_git_branch" if not defined DCLOUD_GIT_BRANCH set /p DCLOUD_GIT_BRANCH=<"%REPO_ROOT%\.dcloud_git_branch"

set "DCLOUD_REPO_ROOT=%REPO_ROOT%"
set "DCLOUD_CONFIG_FILE=%CONFIG_FILE%"
"%VENV_PYTHON%" "%CONFIG_HELPER%"
if errorlevel 1 exit /b 1

call :maybe_add_firewall_rules

where php-cgi >nul 2>nul
if errorlevel 1 where php >nul 2>nul
if errorlevel 1 (
  echo [dcloud-windows-python] Hinweis: php-cgi/php wurde nicht gefunden. PHP-Webseiten sind erst nach PHP-Installation verfuegbar.
)

exit /b 0

:find_python
call :add_known_python_paths
set "PYTHON_EXE="
for /f "usebackq delims=" %%P in (`py -3 -c "import sys; print(sys.executable)" 2^>nul`) do set "PYTHON_EXE=%%P"
if defined PYTHON_EXE goto :python_found
for /f "usebackq delims=" %%P in (`python -c "import sys; print(sys.executable)" 2^>nul`) do set "PYTHON_EXE=%%P"
if defined PYTHON_EXE goto :python_found

if /I "%DCLOUD_AUTO_INSTALL_PYTHON%"=="0" goto :python_missing_manual

echo [dcloud-windows-python] Python 3 was not found. Trying automatic Python installation...
call :install_python_runtime
if errorlevel 1 exit /b 1
call :add_known_python_paths

set "PYTHON_EXE="
for /f "usebackq delims=" %%P in (`py -3 -c "import sys; print(sys.executable)" 2^>nul`) do set "PYTHON_EXE=%%P"
if defined PYTHON_EXE goto :python_found
for /f "usebackq delims=" %%P in (`python -c "import sys; print(sys.executable)" 2^>nul`) do set "PYTHON_EXE=%%P"
if defined PYTHON_EXE goto :python_found

echo [dcloud-windows-python] ERROR: Python was installed, but this CMD session cannot find it yet.
echo Close this CMD window, open a new CMD window, and run the command again.
exit /b 1

:python_missing_manual
echo [dcloud-windows-python] ERROR: Python 3 was not found.
echo Automatic installation is disabled by DCLOUD_AUTO_INSTALL_PYTHON=0.
echo Install Python 3.10 or newer first, then run this command again.
echo Download: https://www.python.org/downloads/windows/
echo During installation, enable "Add python.exe to PATH".
exit /b 1

:python_found
"%PYTHON_EXE%" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
if errorlevel 1 (
  if /I "%DCLOUD_AUTO_INSTALL_PYTHON%"=="0" (
    echo [dcloud-windows-python] ERROR: Python 3.10 or newer is required.
    "%PYTHON_EXE%" --version
    exit /b 1
  )
  echo [dcloud-windows-python] Existing Python is too old. Trying automatic Python upgrade/install...
  "%PYTHON_EXE%" --version
  call :install_python_runtime
  if errorlevel 1 exit /b 1
  call :add_known_python_paths
  set "PYTHON_EXE="
  for /f "usebackq delims=" %%P in (`py -3 -c "import sys; print(sys.executable)" 2^>nul`) do set "PYTHON_EXE=%%P"
  if defined PYTHON_EXE goto :python_found
  for /f "usebackq delims=" %%P in (`python -c "import sys; print(sys.executable)" 2^>nul`) do set "PYTHON_EXE=%%P"
  if defined PYTHON_EXE goto :python_found
  echo [dcloud-windows-python] ERROR: Python 3.10+ was installed, but this CMD session cannot find it yet.
  echo Close this CMD window, open a new CMD window, and run the command again.
  exit /b 1
)
echo [dcloud-windows-python] Python: %PYTHON_EXE%
exit /b 0

:install_python_runtime
call :add_known_python_paths
where winget >nul 2>nul
if not errorlevel 1 (
  echo [dcloud-windows-python] Installing Python with winget package %DCLOUD_PYTHON_WINGET_ID%...
  winget install --id %DCLOUD_PYTHON_WINGET_ID% -e --source winget --silent --accept-package-agreements --accept-source-agreements
  if not errorlevel 1 exit /b 0
  echo [dcloud-windows-python] WARNING: winget Python installation failed. Trying Chocolatey fallback...
) else (
  echo [dcloud-windows-python] winget was not found. Trying Chocolatey fallback...
)

call :require_admin_for_python_install
if errorlevel 1 exit /b 1
call :ensure_chocolatey
if errorlevel 1 exit /b 1

echo [dcloud-windows-python] Installing Python with Chocolatey...
choco install python -y --no-progress
if errorlevel 1 (
  echo [dcloud-windows-python] ERROR: Python installation via Chocolatey failed.
  exit /b 1
)
exit /b 0

:require_admin_for_python_install
net session >nul 2>nul
if not errorlevel 1 exit /b 0
echo [dcloud-windows-python] Chocolatey fallback requires Administrator rights.
echo Open CMD as Administrator and run the command again, or install Python 3.10+ manually.
echo To disable automatic Python installation, run: set DCLOUD_AUTO_INSTALL_PYTHON=0
exit /b 1

:ensure_chocolatey
where choco >nul 2>nul
if not errorlevel 1 exit /b 0

if exist "%ProgramData%\chocolatey\bin\choco.exe" (
  set "PATH=%ProgramData%\chocolatey\bin;%PATH%"
  exit /b 0
)

echo [dcloud-windows-python] Chocolatey was not found. Installing Chocolatey...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
if errorlevel 1 (
  echo [dcloud-windows-python] ERROR: Chocolatey installation failed.
  exit /b 1
)
set "PATH=%ProgramData%\chocolatey\bin;%PATH%"
where choco >nul 2>nul
if errorlevel 1 (
  echo [dcloud-windows-python] ERROR: Chocolatey was installed, but choco.exe is not available yet.
  echo Please open a new Administrator CMD window and run the command again.
  exit /b 1
)
exit /b 0

:add_known_python_paths
if exist "%LocalAppData%\Microsoft\WindowsApps" set "PATH=%LocalAppData%\Microsoft\WindowsApps;%PATH%"
if exist "%LocalAppData%\Programs\Python\Python314" set "PATH=%LocalAppData%\Programs\Python\Python314;%LocalAppData%\Programs\Python\Python314\Scripts;%PATH%"
if exist "%LocalAppData%\Programs\Python\Python313" set "PATH=%LocalAppData%\Programs\Python\Python313;%LocalAppData%\Programs\Python\Python313\Scripts;%PATH%"
if exist "%LocalAppData%\Programs\Python\Python312" set "PATH=%LocalAppData%\Programs\Python\Python312;%LocalAppData%\Programs\Python\Python312\Scripts;%PATH%"
if exist "%LocalAppData%\Programs\Python\Python311" set "PATH=%LocalAppData%\Programs\Python\Python311;%LocalAppData%\Programs\Python\Python311\Scripts;%PATH%"
if exist "%LocalAppData%\Programs\Python\Python310" set "PATH=%LocalAppData%\Programs\Python\Python310;%LocalAppData%\Programs\Python\Python310\Scripts;%PATH%"
if exist "%ProgramFiles%\Python314" set "PATH=%ProgramFiles%\Python314;%ProgramFiles%\Python314\Scripts;%PATH%"
if exist "%ProgramFiles%\Python313" set "PATH=%ProgramFiles%\Python313;%ProgramFiles%\Python313\Scripts;%PATH%"
if exist "%ProgramFiles%\Python312" set "PATH=%ProgramFiles%\Python312;%ProgramFiles%\Python312\Scripts;%PATH%"
if exist "%ProgramFiles%\Python311" set "PATH=%ProgramFiles%\Python311;%ProgramFiles%\Python311\Scripts;%PATH%"
if exist "%ProgramFiles%\Python310" set "PATH=%ProgramFiles%\Python310;%ProgramFiles%\Python310\Scripts;%PATH%"
if exist "%ProgramData%\chocolatey\bin" set "PATH=%ProgramData%\chocolatey\bin;%PATH%"
exit /b 0

:start_service
call :is_running
if not errorlevel 1 (
  call :read_pid
  echo [dcloud-windows-python] dcloud is already running with PID %DCLOUD_PID%.
  echo Dashboard: http://127.0.0.1:%DCLOUD_DASHBOARD_PORT%
  exit /b 0
)

type nul >> "%LOG_FILE%"
type nul >> "%ERR_FILE%"

set "DCLOUD_START_PYTHON=%VENV_PYTHON%"
set "DCLOUD_REPO_ROOT=%REPO_ROOT%"
set "DCLOUD_CONFIG_FILE=%CONFIG_FILE%"
set "DCLOUD_LOG_FILE=%LOG_FILE%"
set "DCLOUD_ERR_FILE=%ERR_FILE%"
set "DCLOUD_PID_FILE=%PID_FILE%"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $env:PYTHONUNBUFFERED='1'; $p=Start-Process -FilePath $env:DCLOUD_START_PYTHON -ArgumentList @('-u','-m','dcloud_client.main','--config',$env:DCLOUD_CONFIG_FILE) -WorkingDirectory $env:DCLOUD_REPO_ROOT -RedirectStandardOutput $env:DCLOUD_LOG_FILE -RedirectStandardError $env:DCLOUD_ERR_FILE -WindowStyle Hidden -PassThru; Set-Content -LiteralPath $env:DCLOUD_PID_FILE -Value $p.Id -Encoding ASCII"
if errorlevel 1 (
  echo [dcloud-windows-python] ERROR: Could not start dcloud.
  exit /b 1
)

timeout /t 3 /nobreak >nul
call :is_running
if errorlevel 1 (
  echo [dcloud-windows-python] ERROR: dcloud stopped immediately. Last error log lines:
  powershell -NoProfile -ExecutionPolicy Bypass -Command "if (Test-Path $env:DCLOUD_ERR_FILE) { Get-Content -Path $env:DCLOUD_ERR_FILE -Tail 80 }"
  exit /b 1
)
call :read_pid
echo [dcloud-windows-python] dcloud started with PID %DCLOUD_PID%.
echo [dcloud-windows-python] Dashboard: http://127.0.0.1:%DCLOUD_DASHBOARD_PORT%
echo [dcloud-windows-python] Data: %DCLOUD_WINDOWS_DATA_DIR%
echo [dcloud-windows-python] Logs: Script\install_windows_python.cmd -Logs
exit /b 0

:run_foreground
echo [dcloud-windows-python] Running in this CMD window. Stop with Ctrl+C.
echo [dcloud-windows-python] Dashboard: http://127.0.0.1:%DCLOUD_DASHBOARD_PORT%
set "DCLOUD_REPO_ROOT=%REPO_ROOT%"
set "DCLOUD_CONFIG_FILE=%CONFIG_FILE%"
cd /d "%REPO_ROOT%"
"%VENV_PYTHON%" -u -m dcloud_client.main --config "%CONFIG_FILE%"
exit /b %ERRORLEVEL%

:restart_service
call :stop_service_silent
call :install_python_app
if errorlevel 1 exit /b 1
goto :start_service

:stop_service
call :stop_service_silent
exit /b %ERRORLEVEL%

:stop_service_silent
call :read_pid
if not defined DCLOUD_PID (
  echo [dcloud-windows-python] dcloud is not running.
  exit /b 0
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$pidValue=$env:DCLOUD_PID; if ($pidValue) { $p=Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue; if ($p) { Stop-Process -Id $p.Id -Force } }"
if errorlevel 1 (
  echo [dcloud-windows-python] WARNING: Could not stop PID %DCLOUD_PID%.
)
del "%PID_FILE%" >nul 2>nul
echo [dcloud-windows-python] dcloud stopped.
exit /b 0

:show_status
call :is_running
if errorlevel 1 (
  echo [dcloud-windows-python] dcloud is not running.
  if exist "%CONFIG_FILE%" echo Config: %CONFIG_FILE%
  exit /b 1
)
call :read_pid
echo [dcloud-windows-python] dcloud is running with PID %DCLOUD_PID%.
echo Dashboard: http://127.0.0.1:%DCLOUD_DASHBOARD_PORT%
echo Config: %CONFIG_FILE%
exit /b 0

:show_logs
mkdir "%LOG_DIR%" 2>nul
type nul >> "%LOG_FILE%"
type nul >> "%ERR_FILE%"
echo [dcloud-windows-python] Showing logs. Stop with Ctrl+C.
set "DCLOUD_LOG_FILE=%LOG_FILE%"
set "DCLOUD_ERR_FILE=%ERR_FILE%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Content -Path $env:DCLOUD_LOG_FILE,$env:DCLOUD_ERR_FILE -Tail 100 -Wait"
exit /b %ERRORLEVEL%

:read_pid
set "DCLOUD_PID="
if exist "%PID_FILE%" for /f "usebackq delims=" %%P in ("%PID_FILE%") do set "DCLOUD_PID=%%P"
set "DCLOUD_PID=%DCLOUD_PID: =%"
exit /b 0

:is_running
call :read_pid
if not defined DCLOUD_PID exit /b 1
tasklist /FI "PID eq %DCLOUD_PID%" 2>nul | find "%DCLOUD_PID%" >nul
exit /b %ERRORLEVEL%

:maybe_add_firewall_rules
if /I "%DCLOUD_ADD_FIREWALL_RULE%"=="0" exit /b 0
net session >nul 2>nul
if errorlevel 1 (
  echo [dcloud-windows-python] Hinweis: Keine Administratorrechte. Windows-Firewall-Regeln werden nicht automatisch gesetzt.
  echo [dcloud-windows-python] Lokal funktioniert das Dashboard trotzdem ueber http://127.0.0.1:%DCLOUD_DASHBOARD_PORT%
  exit /b 0
)
netsh advfirewall firewall add rule name="dcloud Dashboard %DCLOUD_DASHBOARD_PORT%" dir=in action=allow protocol=TCP localport=%DCLOUD_DASHBOARD_PORT% >nul 2>nul
netsh advfirewall firewall add rule name="dcloud UDP Discovery %DCLOUD_DISCOVERY_UDP_PORT%" dir=in action=allow protocol=UDP localport=%DCLOUD_DISCOVERY_UDP_PORT% >nul 2>nul
exit /b 0
