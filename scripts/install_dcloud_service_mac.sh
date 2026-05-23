#!/usr/bin/env bash
set -euo pipefail

# dcloud Installer für macOS (launchd)
# Beispiel:
#   curl -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/scripts/install_dcloud_service_mac.sh | bash -s -- --role server --storage-gb 200 --enable-smb

ROLE="server"
STORAGE_GB="50"
ENABLE_SMB="false"
SMB_USER=""
SMB_PASS=""
INSTALL_DIR="${HOME}/dcloud"
SERVICE_NAME="de.tmp-networks.dcloud"

usage() {
  cat <<USAGE
Usage: $0 [options]
  --role server          Node-Rolle (default: server)
  --storage-gb N            Freigegebener Speicher in GB, min. 5 (default: 50)
  --enable-smb              SMB aktivieren
  --disable-smb             SMB deaktivieren
  --smb-user USER           SMB Benutzername
  --smb-pass PASS           SMB Passwort
  --install-dir PATH        Installationsverzeichnis (default: ~/dcloud)
  --service-name NAME       launchd Label (default: de.tmp-networks.dcloud)
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

if [ "$(uname -s)" != "Darwin" ]; then
  echo "Dieses Skript ist nur für macOS (Darwin)." >&2
  exit 1
fi

LIMIT_BYTES=$((STORAGE_GB * 1024 * 1024 * 1024))

ensure_runtime_macos() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 fehlt. Bitte zuerst installieren (z. B. via 'brew install python')." >&2
    exit 1
  fi
  if ! command -v git >/dev/null 2>&1; then
    echo "git fehlt. Bitte zuerst Xcode Command Line Tools installieren: xcode-select --install" >&2
    exit 1
  fi
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

write_config() {
  local config_path="$1"
  cat > "$config_path" <<CFG
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

setup_launchd() {
  local plist_path="$HOME/Library/LaunchAgents/${SERVICE_NAME}.plist"
  mkdir -p "$(dirname "$plist_path")"

  cat > "$plist_path" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${SERVICE_NAME}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_DIR}/.venv/bin/python</string>
    <string>-m</string>
    <string>dcloud_client.main</string>
    <string>--config</string>
    <string>${INSTALL_DIR}/config.yml</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${INSTALL_DIR}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${INSTALL_DIR}/logs/dcloud.out.log</string>
  <key>StandardErrorPath</key>
  <string>${INSTALL_DIR}/logs/dcloud.err.log</string>
</dict>
</plist>
PLIST

  mkdir -p "$INSTALL_DIR/logs"
  launchctl unload "$plist_path" >/dev/null 2>&1 || true
  launchctl load "$plist_path"
}

setup_launchd_auto_update() {
  local update_script="${INSTALL_DIR}/update_dcloud.sh"
  cat > "$update_script" <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
cd "${INSTALL_DIR}"

if [ ! -d .git ]; then
  exit 0
fi

git remote update --prune
LOCAL_SHA=\$(git rev-parse @)
REMOTE_SHA=\$(git rev-parse @{u})

if [ "\$LOCAL_SHA" = "\$REMOTE_SHA" ]; then
  exit 0
fi

launchctl unload "$HOME/Library/LaunchAgents/${SERVICE_NAME}.plist" >/dev/null 2>&1 || true
git pull --ff-only
"${INSTALL_DIR}/.venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
launchctl load "$HOME/Library/LaunchAgents/${SERVICE_NAME}.plist"
SCRIPT
  chmod +x "$update_script"

  local plist_path="$HOME/Library/LaunchAgents/${SERVICE_NAME}.autoupdate.plist"
  cat > "$plist_path" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${SERVICE_NAME}.autoupdate</string>
  <key>ProgramArguments</key>
  <array>
    <string>${update_script}</string>
  </array>
  <key>StartInterval</key>
  <integer>300</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${INSTALL_DIR}/logs/dcloud.autoupdate.out.log</string>
  <key>StandardErrorPath</key>
  <string>${INSTALL_DIR}/logs/dcloud.autoupdate.err.log</string>
</dict>
</plist>
PLIST
  launchctl unload "$plist_path" >/dev/null 2>&1 || true
  launchctl load "$plist_path"
}

main() {
  ensure_runtime_macos
  install_repo
  setup_python_venv
  write_config "$INSTALL_DIR/config.yml"
  setup_launchd
  setup_launchd_auto_update
  cat <<DONE
✅ dcloud wurde auf macOS eingerichtet.
Service-Label: $SERVICE_NAME
Installationspfad: $INSTALL_DIR
Web UI: http://127.0.0.1:8787
Verwalten:
  launchctl list | grep "$SERVICE_NAME"
  launchctl unload "$HOME/Library/LaunchAgents/${SERVICE_NAME}.plist"
  launchctl load "$HOME/Library/LaunchAgents/${SERVICE_NAME}.plist"
DONE
}

main "$@"
