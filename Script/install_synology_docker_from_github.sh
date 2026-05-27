#!/bin/sh
# dcloud Synology Docker GitHub bootstrap installer
#
# Lädt das Projekt direkt von GitHub herunter und startet danach
# Script/install_synology_docker.sh aus dem heruntergeladenen Projekt.
#
# Standard-Aufruf auf der Synology per SSH:
#   curl -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/Script/install_synology_docker_from_github.sh | sh
#
# Mit Anpassungen:
#   curl -fsSL https://raw.githubusercontent.com/MTSmash-TMP-Networks/Projekt-dcloud/main/Script/install_synology_docker_from_github.sh | \
#     DCLOUD_NODE_NAME=mein-peer CONTAINER_NAME=dcloud-mein-peer DCLOUD_DASHBOARD_PORT=8787 sh
#
# Ohne DCLOUD_NODE_NAME/CONTAINER_NAME erzeugt das Installationsskript automatisch
# eindeutige Namen aus Synology-Hostname plus stabilem Geräte-Suffix.

set -eu

REPO_OWNER="${DCLOUD_GITHUB_OWNER:-MTSmash-TMP-Networks}"
REPO_NAME="${DCLOUD_GITHUB_REPO:-Projekt-dcloud}"
REPO_BRANCH="${DCLOUD_GITHUB_BRANCH:-main}"
BOOTSTRAP_DIR="${DCLOUD_BOOTSTRAP_DIR:-/tmp/dcloud-synology-github-install}"
INSTALL_DIR="${INSTALL_DIR:-/volume1/docker/dcloud}"
DCLOUD_UPDATE_ONLY="${DCLOUD_UPDATE_ONLY:-0}"
DCLOUD_FORCE_UPDATE="${DCLOUD_FORCE_UPDATE:-0}"
ARCHIVE_FILE="$BOOTSTRAP_DIR/project.tar.gz"
DOWNLOAD_URL="https://github.com/$REPO_OWNER/$REPO_NAME/archive/refs/heads/$REPO_BRANCH.tar.gz"
REF_API_URL="https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/git/ref/heads/$REPO_BRANCH"

log() {
    printf '%s\n' "[dcloud-github-bootstrap] $*"
}

fail() {
    printf '%s\n' "[dcloud-github-bootstrap] FEHLER: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 wurde nicht gefunden. Bitte auf der Synology installieren/aktivieren."
}

download_file() {
    src="$1"
    dst="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$src" -o "$dst"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dst" "$src"
    else
        fail "curl oder wget wurde nicht gefunden. Bitte curl installieren oder DSM-Paketquellen prüfen."
    fi
}

fetch_text() {
    src="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$src" 2>/dev/null || true
    elif command -v wget >/dev/null 2>&1; then
        wget -qO - "$src" 2>/dev/null || true
    else
        true
    fi
}

lookup_github_revision() {
    json=$(fetch_text "$REF_API_URL")
    value=$(printf '%s' "$json" | sed -n 's/.*"sha"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F][0-9a-fA-F]*\)".*/\1/p' | head -n 1 | cut -c1-12)
    if [ -n "$value" ]; then
        printf '%s' "$value"
    else
        printf '%s' "unbekannt"
    fi
}

require_cmd tar
require_cmd docker

CURRENT_REVISION=""
if [ -f "$INSTALL_DIR/app/.dcloud_git_revision" ]; then
    CURRENT_REVISION=$(head -n 1 "$INSTALL_DIR/app/.dcloud_git_revision" 2>/dev/null | tr -d '\r\n' || true)
fi

log "Bootstrap-Verzeichnis: $BOOTSTRAP_DIR"
rm -rf "$BOOTSTRAP_DIR"
mkdir -p "$BOOTSTRAP_DIR"

log "Projekt wird von GitHub geladen: $REPO_OWNER/$REPO_NAME ($REPO_BRANCH)"
DCLOUD_GIT_REVISION="${DCLOUD_GIT_REVISION:-$(lookup_github_revision)}"
DCLOUD_GIT_BRANCH="${DCLOUD_GIT_BRANCH:-$REPO_BRANCH}"
log "GitHub-Stand: $DCLOUD_GIT_REVISION ($DCLOUD_GIT_BRANCH)"
if [ "$DCLOUD_UPDATE_ONLY" = "1" ] && [ "$DCLOUD_FORCE_UPDATE" != "1" ] && [ -n "$CURRENT_REVISION" ] && [ "$CURRENT_REVISION" != "unbekannt" ] && [ "$DCLOUD_GIT_REVISION" != "unbekannt" ] && [ "$CURRENT_REVISION" = "$DCLOUD_GIT_REVISION" ]; then
    log "Kein GitHub-Update verfuegbar. Aktueller Stand ist bereits $CURRENT_REVISION."
    if [ -f "$INSTALL_DIR/app/docker-compose.synology.yml" ]; then
        cd "$INSTALL_DIR/app"
        if docker compose version >/dev/null 2>&1; then
            docker compose -f docker-compose.synology.yml ps >/dev/null 2>&1 || true
        elif command -v docker-compose >/dev/null 2>&1; then
            docker-compose -f docker-compose.synology.yml ps >/dev/null 2>&1 || true
        fi
    fi
    exit 0
fi
download_file "$DOWNLOAD_URL" "$ARCHIVE_FILE"

log "Archiv wird entpackt."
tar -xzf "$ARCHIVE_FILE" -C "$BOOTSTRAP_DIR"

PROJECT_DIR=""
for candidate in "$BOOTSTRAP_DIR"/*; do
    if [ -d "$candidate" ] && [ -f "$candidate/requirements.txt" ] && [ -d "$candidate/dcloud_client" ]; then
        PROJECT_DIR="$candidate"
        break
    fi
done

if [ -z "$PROJECT_DIR" ]; then
    fail "Das heruntergeladene GitHub-Archiv enthält kein gültiges dcloud-Projekt."
fi

if [ ! -f "$PROJECT_DIR/Script/install_synology_docker.sh" ]; then
    fail "Script/install_synology_docker.sh wurde im GitHub-Archiv nicht gefunden. Bitte Repository aktualisieren."
fi

printf '%s\n' "$DCLOUD_GIT_REVISION" > "$PROJECT_DIR/.dcloud_git_revision"
printf '%s\n' "$DCLOUD_GIT_BRANCH" > "$PROJECT_DIR/.dcloud_git_branch"
export DCLOUD_GIT_REVISION DCLOUD_GIT_BRANCH

log "Starte Synology-Docker-Installation aus: $PROJECT_DIR"
sh "$PROJECT_DIR/Script/install_synology_docker.sh"
