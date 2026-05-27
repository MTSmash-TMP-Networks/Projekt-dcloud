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
#     DCLOUD_NODE_NAME=mein-peer DCLOUD_DASHBOARD_PORT=8787 sh

set -eu

REPO_OWNER="${DCLOUD_GITHUB_OWNER:-MTSmash-TMP-Networks}"
REPO_NAME="${DCLOUD_GITHUB_REPO:-Projekt-dcloud}"
REPO_BRANCH="${DCLOUD_GITHUB_BRANCH:-main}"
BOOTSTRAP_DIR="${DCLOUD_BOOTSTRAP_DIR:-/tmp/dcloud-synology-github-install}"
ARCHIVE_FILE="$BOOTSTRAP_DIR/project.tar.gz"
DOWNLOAD_URL="https://github.com/$REPO_OWNER/$REPO_NAME/archive/refs/heads/$REPO_BRANCH.tar.gz"

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

require_cmd tar
require_cmd docker

log "Bootstrap-Verzeichnis: $BOOTSTRAP_DIR"
rm -rf "$BOOTSTRAP_DIR"
mkdir -p "$BOOTSTRAP_DIR"

log "Projekt wird von GitHub geladen: $REPO_OWNER/$REPO_NAME ($REPO_BRANCH)"
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

log "Starte Synology-Docker-Installation aus: $PROJECT_DIR"
sh "$PROJECT_DIR/Script/install_synology_docker.sh"
