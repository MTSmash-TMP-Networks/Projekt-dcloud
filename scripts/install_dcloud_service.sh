#!/usr/bin/env sh
set -eu

# dcloud Service Installer (Linux / OpenWrt / Windows bootstrap)
# Beispiel via curl:
#   curl -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/scripts/install_dcloud_service.sh | sh -s -- --role server --storage-gb 200 --enable-smb

ROLE="pc"
STORAGE_GB="50"
ENABLE_SMB="false"
SMB_USER=""
SMB_PASS=""
INSTALL_DIR="/opt/dcloud"
SERVICE_NAME="dcloud"
TARGET_OS="auto"

usage() {
  cat <<USAGE
Usage: $0 [options]
  --role pc|server          Node-Rolle (default: pc)
  --storage-gb N            Freigegebener Speicher in GB, min. 5 (default: 50)
  --enable-smb              SMB aktivieren
  --disable-smb             SMB deaktivieren
  --smb-user USER           SMB Benutzername
  --smb-pass PASS           SMB Passwort
  --install-dir PATH        Installationsverzeichnis (default: /opt/dcloud)
  --service-name NAME       Service-Name (default: dcloud)
  --target auto|linux|openwrt|windows
  -h, --help                Hilfe
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --role) ROLE="$2"; shift 2 ;;
    --storage-gb) STORAGE_GB="$2"; shift 2 ;;
    --enable-smb) ENABLE_SMB="true"; shift ;;
    --disable-smb) ENABLE_SMB="false"; shift ;;
    --smb-user) SMB_USER="$2"; shift 2 ;;
    --smb-pass) SMB_PASS="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --service-name) SERVICE_NAME="$2"; shift 2 ;;
    --target) TARGET_OS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; usage; exit 1 ;;
  esac
done

case "$ROLE" in
  pc|server) ;;
  *) echo "--role muss pc oder server sein" >&2; exit 1 ;;
esac

case "$STORAGE_GB" in
  ''|*[!0-9]*) echo "--storage-gb muss eine Zahl sein" >&2; exit 1 ;;
esac

if [ "$STORAGE_GB" -lt 5 ]; then
  echo "--storage-gb muss mindestens 5 sein" >&2
  exit 1
fi

if [ "$TARGET_OS" = "auto" ]; then
  UNAME_S="$(uname -s | tr '[:upper:]' '[:lower:]')"
  if echo "$UNAME_S" | grep -q "mingw\|msys\|cygwin"; then
    TARGET_OS="windows"
  elif [ -f /etc/openwrt_release ]; then
    TARGET_OS="openwrt"
  else
    TARGET_OS="linux"
  fi
fi

LIMIT_BYTES=$((STORAGE_GB * 1024 * 1024 * 1024))

ensure_runtime_linux() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y python3 python3-venv python3-pip
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 python3-pip
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm python python-pip
  elif command -v zypper >/dev/null 2>&1; then
    zypper install -y python3 python3-pip
  fi
}

write_config() {
  CONFIG_PATH="$1"
  cat > "$CONFIG_PATH" <<CFG
node:
  name: dcloud-node
  identity_path: ./storage/identity
  client_type: $ROLE
storage:
  path: ./storage
  limit_bytes: $LIMIT_BYTES
  min_free_bytes: 1073741824
  chunk_size_bytes: 4194304
web:
  host: 0.0.0.0
  port: 8787
network:
  udp_host: 0.0.0.0
  udp_port: 6881
  udp_port_range:
    start: 6881
    end: 6891
  bootstrap_nodes: []
  tree_parent_nodes: []
  relay_children: false
  discovery_interval_seconds: 10
  auto_discovery_enabled: true
  auto_discovery_ports: [6881]
  auto_discovery_hosts: [255.255.255.255]
  startup_discovery_seconds: 12
  startup_discovery_interval_seconds: 2
  peer_timeout_seconds: 35
  peer_cleanup_interval_seconds: 5
  relay_url: "https://support.tmp-networks.de/dcstorage/dcloud_relay.php"
  relay_urls: ["https://support.tmp-networks.de/dcstorage/dcloud_relay.php"]
  relay_secret: ""
  relay_poll_interval_seconds: 1
  relay_request_timeout_seconds: 180
  relay_chunk_size_bytes: 524288
security:
  protocol_magic: DCLOUD1
smb:
  enabled: $ENABLE_SMB
  host: 0.0.0.0
  port: 445
  share_name: DCLOUD
  username: "$SMB_USER"
  password: "$SMB_PASS"
CFG
}

install_repo() {
  mkdir -p "$INSTALL_DIR"
  if [ -d "$INSTALL_DIR/.git" ]; then
    git -C "$INSTALL_DIR" pull --ff-only
  else
    git clone https://github.com/MTSmash-TMP-Networks/Projekt-dcloud.git "$INSTALL_DIR"
  fi
}

setup_python_venv() {
  cd "$INSTALL_DIR"
  python3 -m venv .venv
  . .venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt
}

setup_systemd() {
  SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
  cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=dcloud client service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/.venv/bin/python -m dcloud_client.main --config $INSTALL_DIR/config.yml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
}

setup_openwrt_init() {
  INIT_FILE="/etc/init.d/${SERVICE_NAME}"
  cat > "$INIT_FILE" <<INIT
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1

start_service() {
  procd_open_instance
  procd_set_param command $INSTALL_DIR/.venv/bin/python -m dcloud_client.main --config $INSTALL_DIR/config.yml
  procd_set_param respawn
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}
INIT
  chmod +x "$INIT_FILE"
  "$INIT_FILE" enable
  "$INIT_FILE" restart
}

setup_windows_bootstrap() {
  BOOTSTRAP="$INSTALL_DIR/install_windows_service.ps1"
  cat > "$BOOTSTRAP" <<PS
param(
  [string]
  \$ServiceName = "$SERVICE_NAME"
)

Write-Host "Installiere Python-Dependencies..."
Set-Location "$INSTALL_DIR"
py -3 -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt

\$taskName = \$ServiceName
\$action = New-ScheduledTaskAction -Execute "$INSTALL_DIR\\.venv\\Scripts\\python.exe" -Argument "-m dcloud_client.main --config $INSTALL_DIR\\config.yml"
\$trigger = New-ScheduledTaskTrigger -AtStartup
\$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName \$taskName -Action \$action -Trigger \$trigger -Principal \$principal -Force
Start-ScheduledTask -TaskName \$taskName
Write-Host "Fertig. Geplante Aufgabe '\$taskName' ist als Dienst-Ersatz aktiv."
PS
  echo "Windows erkannt. Fuehre als Administrator aus:"
  echo "  powershell -ExecutionPolicy Bypass -File \"$BOOTSTRAP\""
}

case "$TARGET_OS" in
  linux)
    ensure_runtime_linux
    install_repo
    setup_python_venv
    write_config "$INSTALL_DIR/config.yml"
    setup_systemd
    ;;
  openwrt)
    opkg update || true
    opkg install python3 python3-pip git-http ca-bundle || true
    install_repo
    setup_python_venv
    write_config "$INSTALL_DIR/config.yml"
    setup_openwrt_init
    ;;
  windows)
    mkdir -p "$INSTALL_DIR"
    install_repo
    write_config "$INSTALL_DIR/config.yml"
    setup_windows_bootstrap
    ;;
  *)
    echo "Unbekanntes target: $TARGET_OS" >&2
    exit 1
    ;;
esac

echo "Installation abgeschlossen: target=$TARGET_OS role=$ROLE storage=${STORAGE_GB}GB smb=$ENABLE_SMB"
