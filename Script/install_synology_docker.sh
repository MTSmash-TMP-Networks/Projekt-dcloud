#!/bin/sh
# dcloud Synology Docker installer
#
# Nutzung aus entpacktem Projekt auf der Synology per SSH:
#   cd /pfad/zum/entpackten/Projekt-dcloud-main
#   sh Script/install_synology_docker.sh
#
# Komplett automatisch direkt von GitHub:
#   curl -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/Script/install_synology_docker_from_github.sh | sh
#
# Optionale Anpassungen:
#   INSTALL_DIR=/volume1/docker/dcloud DCLOUD_NODE_NAME=mein-peer CONTAINER_NAME=dcloud-mein-peer sh Script/install_synology_docker.sh
#   DCLOUD_DASHBOARD_PORT=8787 DCLOUD_DISCOVERY_UDP_PORT=6881 sh Script/install_synology_docker.sh
#
# Ohne DCLOUD_NODE_NAME/CONTAINER_NAME erzeugt das Skript automatisch eindeutige Namen
# aus Synology-Hostname plus stabilem Geräte-Suffix.

set -eu

make_slug() {
    value="$1"
    slug=$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9][^a-z0-9]*/-/g; s/^-//; s/-$//')
    if [ -z "$slug" ]; then
        slug="synology"
    fi
    printf '%s' "$slug"
}

make_default_instance_name() {
    raw_host=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || printf '%s' synology)
    raw_host=$(printf '%s' "$raw_host" | tr -d '\r\n')
    safe_host=$(make_slug "$raw_host")
    safe_host=$(printf '%s' "$safe_host" | cut -c1-32)
    safe_host=$(make_slug "$safe_host")

    unique_source="$raw_host"
    for mac_path in /sys/class/net/*/address; do
        [ -r "$mac_path" ] || continue
        mac=$(cat "$mac_path" 2>/dev/null || true)
        case "$mac" in
            ""|"00:00:00:00:00:00") continue ;;
        esac
        unique_source="$unique_source-$mac"
        break
    done

    set -- $(printf '%s' "$unique_source" | cksum)
    suffix="$1"
    printf '%s' "dcloud-$safe_host-$suffix"
}

read_git_revision() {
    if [ -n "${DCLOUD_GIT_REVISION:-}" ] && [ "$DCLOUD_GIT_REVISION" != "unbekannt" ]; then
        printf '%s' "$DCLOUD_GIT_REVISION"
        return
    fi
    if [ -f "$PROJECT_ROOT/.dcloud_git_revision" ]; then
        value=$(head -n 1 "$PROJECT_ROOT/.dcloud_git_revision" 2>/dev/null | tr -d '\r\n' || true)
        if [ -n "$value" ] && [ "$value" != "unbekannt" ]; then
            printf '%s' "$value"
            return
        fi
    fi
    if command -v git >/dev/null 2>&1 && [ -d "$PROJECT_ROOT/.git" ]; then
        value=$(git -C "$PROJECT_ROOT" rev-parse --short=12 HEAD 2>/dev/null || true)
        if [ -n "$value" ]; then
            printf '%s' "$value"
            return
        fi
    fi
    printf '%s' "unbekannt"
}

read_git_branch() {
    if [ -n "${DCLOUD_GIT_BRANCH:-}" ]; then
        printf '%s' "$DCLOUD_GIT_BRANCH"
        return
    fi
    if [ -f "$PROJECT_ROOT/.dcloud_git_branch" ]; then
        value=$(head -n 1 "$PROJECT_ROOT/.dcloud_git_branch" 2>/dev/null | tr -d '\r\n' || true)
        if [ -n "$value" ]; then
            printf '%s' "$value"
            return
        fi
    fi
    if command -v git >/dev/null 2>&1 && [ -d "$PROJECT_ROOT/.git" ]; then
        value=$(git -C "$PROJECT_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
        if [ -n "$value" ]; then
            printf '%s' "$value"
            return
        fi
    fi
    printf '%s' "main"
}

APP_NAME="dcloud"
DEFAULT_INSTANCE_NAME=$(make_default_instance_name)
CONTAINER_NAME="${CONTAINER_NAME:-$DEFAULT_INSTANCE_NAME}"
INSTALL_DIR="${INSTALL_DIR:-/volume1/docker/dcloud}"
DCLOUD_DASHBOARD_PORT="${DCLOUD_DASHBOARD_PORT:-8787}"
DCLOUD_DISCOVERY_UDP_PORT="${DCLOUD_DISCOVERY_UDP_PORT:-6881}"
DCLOUD_NODE_NAME="${DCLOUD_NODE_NAME:-$DEFAULT_INSTANCE_NAME}"
DCLOUD_STORAGE_LIMIT_GB="${DCLOUD_STORAGE_LIMIT_GB:-50}"
DCLOUD_RELAY_URLS="${DCLOUD_RELAY_URLS:-}"
DCLOUD_GITHUB_OWNER="${DCLOUD_GITHUB_OWNER:-MTSmash-TMP-Networks}"
DCLOUD_GITHUB_REPO="${DCLOUD_GITHUB_REPO:-Projekt-dcloud}"
DCLOUD_GITHUB_BRANCH="${DCLOUD_GITHUB_BRANCH:-main}"
DCLOUD_ENABLE_AUTO_UPDATE="${DCLOUD_ENABLE_AUTO_UPDATE:-1}"
DCLOUD_AUTO_UPDATE_INTERVAL_MINUTES="${DCLOUD_AUTO_UPDATE_INTERVAL_MINUTES:-5}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
APP_DIR="$INSTALL_DIR/app"
DATA_DIR="$INSTALL_DIR/data"
COMPOSE_FILE="$APP_DIR/docker-compose.synology.yml"
ENV_FILE="$APP_DIR/.env"
DOCKERFILE="$APP_DIR/Dockerfile.synology"
LOG_DIR="$INSTALL_DIR/logs"
UPDATE_SCRIPT="$INSTALL_DIR/update_dcloud_synology.sh"

DCLOUD_GIT_REVISION="$(read_git_revision)"
DCLOUD_GIT_BRANCH="$(read_git_branch)"

log() {
    printf '%s\n' "[dcloud-synology] $*"
}

fail() {
    printf '%s\n' "[dcloud-synology] FEHLER: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 wurde nicht gefunden. Bitte Synology Container Manager/Docker installieren und SSH neu starten."
}

compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        printf '%s' "docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        printf '%s' "docker-compose"
    else
        fail "Docker Compose wurde nicht gefunden. Auf DSM 7 bitte Container Manager installieren."
    fi
}

if [ ! -f "$PROJECT_ROOT/requirements.txt" ] || [ ! -d "$PROJECT_ROOT/dcloud_client" ]; then
    fail "Das Skript muss aus dem entpackten Projekt heraus gestartet werden. Erwartet: requirements.txt und dcloud_client/."
fi

require_cmd docker
COMPOSE=$(compose_cmd)

log "Installationsordner: $INSTALL_DIR"
log "Node-Name: $DCLOUD_NODE_NAME"
log "Container-Name: $CONTAINER_NAME"
log "GitHub-Stand: $DCLOUD_GIT_REVISION ($DCLOUD_GIT_BRANCH)"
mkdir -p "$APP_DIR" "$DATA_DIR" "$DATA_DIR/storage" "$DATA_DIR/logs" "$LOG_DIR"

log "Projektdateien werden nach $APP_DIR kopiert."
if [ "$PROJECT_ROOT" != "$APP_DIR" ]; then
    # Vorhandene App-Dateien ersetzen, persistente Daten bleiben in $DATA_DIR erhalten.
    rm -rf "$APP_DIR"
    mkdir -p "$APP_DIR"
    (cd "$PROJECT_ROOT" && tar cf - .) | (cd "$APP_DIR" && tar xf -)
fi

log "Synology-Dockerfile wird erstellt."
cat > "$DOCKERFILE" <<'DOCKERFILE_EOF'
FROM python:3.11-slim

ARG DCLOUD_GIT_REVISION=unbekannt
ARG DCLOUD_GIT_BRANCH=main

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DCLOUD_CONFIG=/data/config.yml \
    DCLOUD_GIT_REVISION=${DCLOUD_GIT_REVISION} \
    DCLOUD_GIT_BRANCH=${DCLOUD_GIT_BRANCH}

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git php-cli php-cgi \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

COPY . .

RUN printf "%s\n" "$DCLOUD_GIT_REVISION" > /app/.dcloud_git_revision \
    && printf "%s\n" "$DCLOUD_GIT_BRANCH" > /app/.dcloud_git_branch \
    && chmod +x /app/scripts/docker-entrypoint.sh

VOLUME ["/data"]
EXPOSE 8787/tcp 6881/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=3).read()"

ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
CMD ["python", "-m", "dcloud_client.main", "--config", "/data/config.yml"]
DOCKERFILE_EOF

log "Docker-Compose-Datei wird erstellt."
cat > "$COMPOSE_FILE" <<'COMPOSE_EOF'
services:
  dcloud:
    build:
      context: .
      dockerfile: Dockerfile.synology
      args:
        DCLOUD_GIT_REVISION: ${DCLOUD_GIT_REVISION:-unbekannt}
        DCLOUD_GIT_BRANCH: ${DCLOUD_GIT_BRANCH:-main}
    image: dcloud:synology
    container_name: ${CONTAINER_NAME:-dcloud-auto}
    restart: unless-stopped
    ports:
      - "${DCLOUD_DASHBOARD_PORT:-8787}:8787/tcp"
      - "${DCLOUD_DISCOVERY_UDP_PORT:-6881}:6881/udp"
    environment:
      DCLOUD_CONFIG: /data/config.yml
      DCLOUD_GIT_REVISION: "${DCLOUD_GIT_REVISION:-unbekannt}"
      DCLOUD_GIT_BRANCH: "${DCLOUD_GIT_BRANCH:-main}"
      DCLOUD_NODE_NAME: "${DCLOUD_NODE_NAME:-dcloud-auto}"
      DCLOUD_WEB_PORT: "8787"
      DCLOUD_UDP_PORT: "6881"
      DCLOUD_STORAGE_LIMIT_GB: "${DCLOUD_STORAGE_LIMIT_GB:-50}"
      DCLOUD_RELAY_URLS: "${DCLOUD_RELAY_URLS:-}"
      DCLOUD_SMB_ENABLED: "false"
    volumes:
      - ../data:/data
COMPOSE_EOF


setup_synology_auto_update() {
    if [ "${DCLOUD_ENABLE_AUTO_UPDATE:-1}" != "1" ]; then
        log "Auto-Update ist deaktiviert."
        return 0
    fi
    mkdir -p "$LOG_DIR"
    cat > "$UPDATE_SCRIPT" <<UPDATE_EOF
#!/bin/sh
export INSTALL_DIR="$INSTALL_DIR"
export DCLOUD_GITHUB_OWNER="$DCLOUD_GITHUB_OWNER"
export DCLOUD_GITHUB_REPO="$DCLOUD_GITHUB_REPO"
export DCLOUD_GITHUB_BRANCH="$DCLOUD_GITHUB_BRANCH"
export CONTAINER_NAME="$CONTAINER_NAME"
export DCLOUD_NODE_NAME="$DCLOUD_NODE_NAME"
export DCLOUD_DASHBOARD_PORT="$DCLOUD_DASHBOARD_PORT"
export DCLOUD_DISCOVERY_UDP_PORT="$DCLOUD_DISCOVERY_UDP_PORT"
export DCLOUD_STORAGE_LIMIT_GB="$DCLOUD_STORAGE_LIMIT_GB"
export DCLOUD_RELAY_URLS="$DCLOUD_RELAY_URLS"
export DCLOUD_ENABLE_AUTO_UPDATE="1"
export DCLOUD_UPDATE_ONLY="1"
LOG_FILE="$LOG_DIR/autoupdate.log"
echo "[\$(date -u +%Y-%m-%dT%H:%M:%SZ)] Suche nach dcloud GitHub-Update..." >> "\$LOG_FILE"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "https://raw.githubusercontent.com/\$DCLOUD_GITHUB_OWNER/\$DCLOUD_GITHUB_REPO/\$DCLOUD_GITHUB_BRANCH/Script/install_synology_docker_from_github.sh" | sh >> "\$LOG_FILE" 2>&1
elif command -v wget >/dev/null 2>&1; then
    wget -qO - "https://raw.githubusercontent.com/\$DCLOUD_GITHUB_OWNER/\$DCLOUD_GITHUB_REPO/\$DCLOUD_GITHUB_BRANCH/Script/install_synology_docker_from_github.sh" | sh >> "\$LOG_FILE" 2>&1
else
    echo "curl/wget fehlt; Auto-Update kann nicht ausgefuehrt werden." >> "\$LOG_FILE"
    exit 1
fi
UPDATE_EOF
    chmod +x "$UPDATE_SCRIPT"
    log "Auto-Update-Skript: $UPDATE_SCRIPT"

    if [ -w /etc/crontab ]; then
        cron_line="*/$DCLOUD_AUTO_UPDATE_INTERVAL_MINUTES * * * * root /bin/sh $UPDATE_SCRIPT >> $LOG_DIR/autoupdate.log 2>&1"
        tmp_cron="$(mktemp)"
        grep -v "${UPDATE_SCRIPT}" /etc/crontab > "$tmp_cron" 2>/dev/null || true
        printf '%s\n' "$cron_line" >> "$tmp_cron"
        cat "$tmp_cron" > /etc/crontab
        rm -f "$tmp_cron"
        if command -v synoservice >/dev/null 2>&1; then
            synoservice --restart crond >/dev/null 2>&1 || true
        elif [ -x /usr/syno/sbin/synoservice ]; then
            /usr/syno/sbin/synoservice --restart crond >/dev/null 2>&1 || true
        elif command -v crond >/dev/null 2>&1; then
            killall crond >/dev/null 2>&1 || true
            crond >/dev/null 2>&1 || true
        fi
        log "Auto-Update aktiv: alle $DCLOUD_AUTO_UPDATE_INTERVAL_MINUTES Minuten."
    else
        log "Auto-Update-Skript wurde erstellt, aber /etc/crontab ist nicht beschreibbar."
        log "Manuelles Update: sh $UPDATE_SCRIPT"
    fi
}

log "Umgebungsdatei wird erstellt."
cat > "$ENV_FILE" <<ENV_EOF
CONTAINER_NAME=$CONTAINER_NAME
DCLOUD_DASHBOARD_PORT=$DCLOUD_DASHBOARD_PORT
DCLOUD_DISCOVERY_UDP_PORT=$DCLOUD_DISCOVERY_UDP_PORT
DCLOUD_NODE_NAME=$DCLOUD_NODE_NAME
DCLOUD_STORAGE_LIMIT_GB=$DCLOUD_STORAGE_LIMIT_GB
DCLOUD_RELAY_URLS=$DCLOUD_RELAY_URLS
DCLOUD_GIT_REVISION=$DCLOUD_GIT_REVISION
DCLOUD_GIT_BRANCH=$DCLOUD_GIT_BRANCH
ENV_EOF

setup_synology_auto_update

log "Container wird gebaut und gestartet."
cd "$APP_DIR"
# shellcheck disable=SC2086
$COMPOSE -f "$COMPOSE_FILE" up -d --build

log "Fertig."
log "Dashboard: http://<SYNOLOGY-IP>:$DCLOUD_DASHBOARD_PORT"
log "Persistente Daten: $DATA_DIR"
log "Container-Logs: cd $APP_DIR && $COMPOSE -f docker-compose.synology.yml logs -f"
