#!/usr/bin/env sh
set -eu

# dcloud Service Installer (Linux / OpenWrt / Windows bootstrap)
# Beispiel via curl:
#   curl -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/scripts/install_dcloud_service.sh | sh -s -- --role server --storage-gb 200 --enable-smb

ROLE="server"
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
  --role server          Node-Rolle (default: server)
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
  server) ;;
  *) echo "--role muss server sein" >&2; exit 1 ;;
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
  compression:
    mode: auto
    algorithm: zlib
    level: 1
    min_savings_percent: 3.0
    min_savings_bytes: 65536
    skip_incompressible: true
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
  relay_url: ""
  relay_urls: []
  relay_secret: ""
  relay_poll_interval_seconds: 0
  relay_request_timeout_seconds: 0
  relay_chunk_size_bytes: 0
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

  VENV_ARGS=""
  VENV_CREATED="false"
  if [ "${TARGET_OS:-}" = "openwrt" ]; then
    VENV_ARGS="--system-site-packages"
  fi

  if [ "${TARGET_OS:-}" = "openwrt" ] && command -v virtualenv >/dev/null 2>&1; then
    if virtualenv $VENV_ARGS .venv >/dev/null 2>&1; then
      VENV_CREATED="true"
    fi
  fi

  if [ "$VENV_CREATED" != "true" ] && python3 -m venv $VENV_ARGS .venv >/dev/null 2>&1; then
    VENV_CREATED="true"
  fi

  if [ "$VENV_CREATED" != "true" ]; then
    echo "⚠️ venv-Erstellung fehlgeschlagen, versuche virtualenv-Fallback..."
    rm -rf .venv

    if ! python3 -m virtualenv $VENV_ARGS .venv 2>/dev/null && ! virtualenv $VENV_ARGS .venv 2>/dev/null; then
      echo "⚠️ virtualenv nicht vorhanden, versuche Installation via pip..."
      python3 -m pip install --upgrade pip virtualenv >/dev/null 2>&1 || true

      if ! python3 -m virtualenv $VENV_ARGS .venv 2>/dev/null; then
        echo "❌ Weder venv noch virtualenv konnten eine Umgebung erstellen." >&2
        echo "   Installiere bitte python3-pip und pruefe freien Speicherplatz (z.B. /opt oder USB)." >&2
        exit 1
      fi
    fi
  fi

  if ! "$INSTALL_DIR/.venv/bin/python" -m pip --version >/dev/null 2>&1; then
    echo "⚠️ pip fehlt in der virtuellen Umgebung, versuche ensurepip..."
    "$INSTALL_DIR/.venv/bin/python" -m ensurepip --upgrade >/dev/null 2>&1 || true
  fi

  if ! "$INSTALL_DIR/.venv/bin/python" -m pip --version >/dev/null 2>&1; then
    echo "❌ pip ist in der virtuellen Umgebung nicht verfuegbar." >&2
    echo "   Installiere python3-pip (opkg) und starte die Installation erneut." >&2
    exit 1
  fi

  "$INSTALL_DIR/.venv/bin/python" -m pip install --upgrade pip
  if [ "${TARGET_OS:-}" = "openwrt" ]; then
    # OpenWrt soll Flask primaer aus opkg nutzen (python3-flask).
    # Fallback auf pip nur falls das Paket im Feed nicht vorhanden ist.
    if ! "$INSTALL_DIR/.venv/bin/python" -c "import flask" >/dev/null 2>&1; then
      "$INSTALL_DIR/.venv/bin/python" -m pip install --no-cache-dir --prefer-binary "Flask>=3.0,<4.0"
    fi
  else
    "$INSTALL_DIR/.venv/bin/python" -m pip install -r requirements.txt
  fi
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

setup_systemd_auto_update() {
  UPDATE_SCRIPT="$INSTALL_DIR/update_dcloud.sh"
  cat > "$UPDATE_SCRIPT" <<SCRIPT
#!/usr/bin/env sh
set -eu
cd "$INSTALL_DIR"

if [ ! -d .git ]; then
  exit 0
fi

git remote update --prune
LOCAL_SHA=\$(git rev-parse @)
REMOTE_SHA=\$(git rev-parse @{u})

if [ "\$LOCAL_SHA" = "\$REMOTE_SHA" ]; then
  exit 0
fi

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Update erkannt, stoppe Dienst $SERVICE_NAME"
systemctl stop "$SERVICE_NAME"
git pull --ff-only
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starte Dienst $SERVICE_NAME neu"
systemctl start "$SERVICE_NAME"
SCRIPT
  chmod +x "$UPDATE_SCRIPT"

  UPDATE_SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}-autoupdate.service"
  cat > "$UPDATE_SERVICE_FILE" <<UNIT
[Unit]
Description=dcloud auto update checker
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$UPDATE_SCRIPT
UNIT

  UPDATE_TIMER_FILE="/etc/systemd/system/${SERVICE_NAME}-autoupdate.timer"
  cat > "$UPDATE_TIMER_FILE" <<UNIT
[Unit]
Description=dcloud auto update timer

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
Unit=${SERVICE_NAME}-autoupdate.service

[Install]
WantedBy=timers.target
UNIT

  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}-autoupdate.timer"
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
  procd_set_param command /bin/sh -c "cd $INSTALL_DIR && exec $INSTALL_DIR/.venv/bin/python -m dcloud_client.main --config $INSTALL_DIR/config.yml"
  procd_set_param respawn
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}
INIT
  chmod +x "$INIT_FILE"
  "$INIT_FILE" enable
  "$INIT_FILE" restart
  sleep 2
  if ! "$INIT_FILE" status >/dev/null 2>&1; then
    echo "⚠️ Dienst $SERVICE_NAME wurde gestartet, meldet aber keinen laufenden Status." >&2
    echo "   Bitte pruefe: logread | tail -n 120" >&2
    return 0
  fi

  WEB_PORT="$(awk '/^[[:space:]]*port:[[:space:]]*[0-9]+[[:space:]]*$/ {print $2; exit}' "$INSTALL_DIR/config.yml" 2>/dev/null || true)"
  [ -n "${WEB_PORT:-}" ] || WEB_PORT="8787"
  ATTEMPTS=10
  while [ "$ATTEMPTS" -gt 0 ]; do
    if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q "[\.\:]$WEB_PORT[[:space:]]"; then
      return 0
    fi
    sleep 1
    ATTEMPTS=$((ATTEMPTS - 1))
  done

  echo "⚠️ Dienst $SERVICE_NAME laeuft, aber Port $WEB_PORT lauscht noch nicht." >&2
  echo "   Bitte pruefe: /etc/init.d/$SERVICE_NAME status" >&2
  echo "   und: logread | tail -n 120" >&2
  if [ -f "$INSTALL_DIR/config.yml" ]; then
    echo "   Konfig-Port laut $INSTALL_DIR/config.yml: $WEB_PORT" >&2
  fi
}

setup_openwrt_auto_update() {
  UPDATE_SCRIPT="/usr/bin/${SERVICE_NAME}_autoupdate.sh"
  cat > "$UPDATE_SCRIPT" <<SCRIPT
#!/bin/sh
set -u

INSTALL_DIR="$INSTALL_DIR"
SERVICE_NAME="$SERVICE_NAME"
LOCK_DIR="/tmp/\${SERVICE_NAME}_autoupdate.lock"
LOCK_ACQUIRED=0
SERVICE_STOPPED=0

log() {
  printf '[%s] %s\n' "\$(date -u +%Y-%m-%dT%H:%M:%SZ)" "\$*"
}

cleanup() {
  rc=\$?
  if [ "\$SERVICE_STOPPED" = "1" ]; then
    log "Autoupdate beendet mit Code \$rc, starte Dienst \$SERVICE_NAME wieder"
    /etc/init.d/"\$SERVICE_NAME" enable >/dev/null 2>&1 || true
    /etc/init.d/"\$SERVICE_NAME" start >/dev/null 2>&1 || true
    sleep 2
    if ! /etc/init.d/"\$SERVICE_NAME" status >/dev/null 2>&1; then
      log "WARNUNG: Dienst \$SERVICE_NAME meldet nach dem Autoupdate keinen laufenden Status"
      /etc/init.d/"\$SERVICE_NAME" restart >/dev/null 2>&1 || true
    fi
  fi
  if [ "\$LOCK_ACQUIRED" = "1" ]; then
    rmdir "\$LOCK_DIR" >/dev/null 2>&1 || true
  fi
  exit "\$rc"
}
trap cleanup EXIT INT TERM

if ! mkdir "\$LOCK_DIR" 2>/dev/null; then
  log "Autoupdate laeuft bereits, ueberspringe diesen Durchlauf"
  exit 0
fi
LOCK_ACQUIRED=1

cd "\$INSTALL_DIR" || exit 1
[ -d .git ] || exit 0

if ! git remote update --prune; then
  log "git remote update fehlgeschlagen, Dienst bleibt unveraendert"
  exit 1
fi

LOCAL_SHA=\$(git rev-parse @ 2>/dev/null || true)
REMOTE_SHA=\$(git rev-parse @{u} 2>/dev/null || true)

if [ -z "\$LOCAL_SHA" ] || [ -z "\$REMOTE_SHA" ]; then
  log "Konnte lokalen oder Remote-Stand nicht ermitteln"
  exit 1
fi

[ "\$LOCAL_SHA" = "\$REMOTE_SHA" ] && exit 0

log "Update erkannt: \$LOCAL_SHA -> \$REMOTE_SHA"
/etc/init.d/"\$SERVICE_NAME" stop >/dev/null 2>&1 || true
SERVICE_STOPPED=1

if ! git pull --ff-only; then
  log "git pull fehlgeschlagen; Dienst wird durch cleanup wieder gestartet"
  exit 1
fi

# OpenWrt nutzt Abhaengigkeiten bevorzugt aus opkg/system-site-packages.
# Ein volles pip install -r requirements.txt kann auf kleinen Routern
# lange bauen oder scheitern und darf den Dienst nicht dauerhaft stoppen.
if [ -x "\$INSTALL_DIR/.venv/bin/python" ]; then
  if ! "\$INSTALL_DIR/.venv/bin/python" - <<'PYDEP' >/dev/null 2>&1
import flask
import yaml
import cryptography
PYDEP
  then
    log "WARNUNG: Python-Abhaengigkeiten unvollstaendig; versuche leichten pip-Fallback"
    if ! "\$INSTALL_DIR/.venv/bin/python" -m pip install --no-cache-dir --prefer-binary "Flask>=3.0,<4.0" "PyYAML>=6.0,<7.0" >/dev/null 2>&1; then
      log "WARNUNG: pip-Fallback fehlgeschlagen; Dienst wird trotzdem neu gestartet"
    fi
  fi
fi

log "Update abgeschlossen; Dienststart erfolgt durch cleanup"
SCRIPT
  chmod +x "$UPDATE_SCRIPT"

  CRON_FILE="/etc/crontabs/root"
  CRON_LINE="*/5 * * * * $UPDATE_SCRIPT >> $INSTALL_DIR/logs/autoupdate.log 2>&1"
  mkdir -p "$INSTALL_DIR/logs"
  touch "$CRON_FILE"
  if ! grep -F "$UPDATE_SCRIPT" "$CRON_FILE" >/dev/null 2>&1; then
    echo "$CRON_LINE" >> "$CRON_FILE"
  fi
  /etc/init.d/cron restart || true
}

setup_openwrt_firewall() {
  if ! command -v uci >/dev/null 2>&1; then
    return 0
  fi

  WEB_PORT="$(awk '/^[[:space:]]*port:[[:space:]]*[0-9]+[[:space:]]*$/ {print $2; exit}' "$INSTALL_DIR/config.yml" 2>/dev/null || true)"
  [ -n "${WEB_PORT:-}" ] || WEB_PORT="8787"

  if ! uci show firewall 2>/dev/null | grep -F "Allow-dcloud-${WEB_PORT}-from-LAN" >/dev/null 2>&1; then
    uci add firewall rule >/dev/null
    uci set firewall.@rule[-1].name="Allow-dcloud-${WEB_PORT}-from-LAN"
    uci set firewall.@rule[-1].src='lan'
    uci set firewall.@rule[-1].proto='tcp'
    uci set firewall.@rule[-1].dest_port="$WEB_PORT"
    uci set firewall.@rule[-1].target='ACCEPT'
  fi

  if ! uci show firewall 2>/dev/null | grep -F "Allow-dcloud-udp-6881-6891-from-LAN" >/dev/null 2>&1; then
    uci add firewall rule >/dev/null
    uci set firewall.@rule[-1].name='Allow-dcloud-udp-6881-6891-from-LAN'
    uci set firewall.@rule[-1].src='lan'
    uci set firewall.@rule[-1].proto='udp'
    uci set firewall.@rule[-1].dest_port='6881-6891'
    uci set firewall.@rule[-1].target='ACCEPT'
  fi

  uci commit firewall || true
  /etc/init.d/firewall restart || true
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
    setup_systemd_auto_update
    ;;
  openwrt)
    opkg update || true
    opkg install python3 python3-pip python3-flask python3-cryptography python3-cffi python3-pycparser python3-yaml git-http ca-bundle || true
    install_repo
    setup_python_venv
    write_config "$INSTALL_DIR/config.yml"
    setup_openwrt_firewall
    setup_openwrt_init
    setup_openwrt_auto_update
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
