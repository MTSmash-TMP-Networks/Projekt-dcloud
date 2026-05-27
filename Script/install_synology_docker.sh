#!/bin/sh
# dcloud Synology Docker installer
#
# Nutzung auf der Synology per SSH:
#   cd /pfad/zum/entpackten/Projekt-dcloud-main
#   sh Script/install_synology_docker.sh
#
# Optionale Anpassungen:
#   INSTALL_DIR=/volume1/docker/dcloud DCLOUD_NODE_NAME=mein-peer sh Script/install_synology_docker.sh
#   DCLOUD_DASHBOARD_PORT=8787 DCLOUD_DISCOVERY_UDP_PORT=6881 sh Script/install_synology_docker.sh

set -eu

APP_NAME="dcloud"
CONTAINER_NAME="${CONTAINER_NAME:-dcloud}"
INSTALL_DIR="${INSTALL_DIR:-/volume1/docker/dcloud}"
DCLOUD_DASHBOARD_PORT="${DCLOUD_DASHBOARD_PORT:-8787}"
DCLOUD_DISCOVERY_UDP_PORT="${DCLOUD_DISCOVERY_UDP_PORT:-6881}"
DCLOUD_NODE_NAME="${DCLOUD_NODE_NAME:-dcloud-synology}"
DCLOUD_STORAGE_LIMIT_GB="${DCLOUD_STORAGE_LIMIT_GB:-50}"
DCLOUD_RELAY_URLS="${DCLOUD_RELAY_URLS:-}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
APP_DIR="$INSTALL_DIR/app"
DATA_DIR="$INSTALL_DIR/data"
COMPOSE_FILE="$APP_DIR/docker-compose.synology.yml"
ENV_FILE="$APP_DIR/.env"
DOCKERFILE="$APP_DIR/Dockerfile.synology"

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
mkdir -p "$APP_DIR" "$DATA_DIR" "$DATA_DIR/storage" "$DATA_DIR/logs"

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

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DCLOUD_CONFIG=/data/config.yml

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl php-cli php-cgi \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

COPY . .

RUN chmod +x /app/scripts/docker-entrypoint.sh

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
    image: dcloud:synology
    container_name: ${CONTAINER_NAME:-dcloud}
    restart: unless-stopped
    ports:
      - "${DCLOUD_DASHBOARD_PORT:-8787}:8787/tcp"
      - "${DCLOUD_DISCOVERY_UDP_PORT:-6881}:6881/udp"
    environment:
      DCLOUD_CONFIG: /data/config.yml
      DCLOUD_NODE_NAME: "${DCLOUD_NODE_NAME:-dcloud-synology}"
      DCLOUD_WEB_PORT: "8787"
      DCLOUD_UDP_PORT: "6881"
      DCLOUD_STORAGE_LIMIT_GB: "${DCLOUD_STORAGE_LIMIT_GB:-50}"
      DCLOUD_RELAY_URLS: "${DCLOUD_RELAY_URLS:-}"
      DCLOUD_SMB_ENABLED: "false"
    volumes:
      - ../data:/data
COMPOSE_EOF

log "Umgebungsdatei wird erstellt."
cat > "$ENV_FILE" <<ENV_EOF
CONTAINER_NAME=$CONTAINER_NAME
DCLOUD_DASHBOARD_PORT=$DCLOUD_DASHBOARD_PORT
DCLOUD_DISCOVERY_UDP_PORT=$DCLOUD_DISCOVERY_UDP_PORT
DCLOUD_NODE_NAME=$DCLOUD_NODE_NAME
DCLOUD_STORAGE_LIMIT_GB=$DCLOUD_STORAGE_LIMIT_GB
DCLOUD_RELAY_URLS=$DCLOUD_RELAY_URLS
ENV_EOF

log "Container wird gebaut und gestartet."
cd "$APP_DIR"
# shellcheck disable=SC2086
$COMPOSE -f "$COMPOSE_FILE" up -d --build

log "Fertig."
log "Dashboard: http://<SYNOLOGY-IP>:$DCLOUD_DASHBOARD_PORT"
log "Persistente Daten: $DATA_DIR"
log "Container-Logs: cd $APP_DIR && $COMPOSE -f docker-compose.synology.yml logs -f"
