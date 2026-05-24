#!/bin/sh
set -eu

CONFIG_PATH="${DCLOUD_CONFIG:-/data/config.yml}"
DATA_DIR="$(dirname "$CONFIG_PATH")"
mkdir -p "$DATA_DIR" /data/storage /data/logs

python - <<'PY'
from __future__ import annotations

import os
import shutil
from pathlib import Path

import yaml

config_path = Path(os.environ.get("DCLOUD_CONFIG", "/data/config.yml"))
source_config = Path("/app/dcloud_client/config.yml")
config_path.parent.mkdir(parents=True, exist_ok=True)
created = not config_path.exists()
if created:
    shutil.copyfile(source_config, config_path)

with config_path.open("r", encoding="utf-8") as fh:
    raw = yaml.safe_load(fh) or {}


def as_bool(value: str | None, default: bool) -> bool:
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled", "ja"}


def as_int(value: str | None, default: int) -> int:
    if value is None or str(value).strip() == "":
        return default
    try:
        return int(str(value).strip())
    except ValueError:
        return default

raw.setdefault("node", {})
raw.setdefault("storage", {})
raw.setdefault("web", {})
raw.setdefault("network", {})
raw.setdefault("smb", {})

# Docker-safe paths. Keep them inside the persistent /data volume.
raw["storage"]["path"] = os.environ.get("DCLOUD_STORAGE_PATH", "/data/storage")
raw["node"]["identity_path"] = os.environ.get("DCLOUD_IDENTITY_PATH", "/data/storage/identity")
raw["web"]["host"] = "0.0.0.0"

if os.environ.get("DCLOUD_NODE_NAME"):
    raw["node"]["name"] = os.environ["DCLOUD_NODE_NAME"].strip() or raw["node"].get("name", "dcloud-node")
if os.environ.get("DCLOUD_WEB_PORT"):
    raw["web"]["port"] = as_int(os.environ.get("DCLOUD_WEB_PORT"), int(raw["web"].get("port", 8787)))
if os.environ.get("DCLOUD_UDP_PORT"):
    udp_port = as_int(os.environ.get("DCLOUD_UDP_PORT"), int(raw["network"].get("udp_port", 6881)))
    raw["network"]["udp_port"] = udp_port
    raw["network"].setdefault("udp_port_range", {"start": udp_port, "end": udp_port})
    raw["network"]["udp_port_range"]["start"] = udp_port
    raw["network"]["udp_port_range"]["end"] = udp_port
    raw["network"]["auto_discovery_ports"] = [udp_port]
if os.environ.get("DCLOUD_STORAGE_LIMIT_GB"):
    gib = max(1, as_int(os.environ.get("DCLOUD_STORAGE_LIMIT_GB"), 50))
    raw["storage"]["limit_bytes"] = gib * 1024 * 1024 * 1024
if os.environ.get("DCLOUD_RELAY_URLS"):
    urls = [u.strip() for u in os.environ["DCLOUD_RELAY_URLS"].split(",") if u.strip()]
    raw["network"]["relay_urls"] = urls

# In Docker for Windows, SMB is off by default because Windows often already owns port 445.
# Preserve dashboard changes after first run unless an explicit env override is supplied.
if created and "DCLOUD_SMB_ENABLED" not in os.environ:
    raw["smb"]["enabled"] = False
if "DCLOUD_SMB_ENABLED" in os.environ:
    raw["smb"]["enabled"] = as_bool(os.environ.get("DCLOUD_SMB_ENABLED"), False)
if os.environ.get("DCLOUD_SMB_PORT"):
    raw["smb"]["port"] = as_int(os.environ.get("DCLOUD_SMB_PORT"), int(raw["smb"].get("port", 445)))
if os.environ.get("DCLOUD_SMB_USER"):
    raw["smb"]["username"] = os.environ["DCLOUD_SMB_USER"]
if os.environ.get("DCLOUD_SMB_PASS"):
    raw["smb"]["password"] = os.environ["DCLOUD_SMB_PASS"]

with config_path.open("w", encoding="utf-8") as fh:
    yaml.safe_dump(raw, fh, sort_keys=False, allow_unicode=True)
PY

exec "$@"
