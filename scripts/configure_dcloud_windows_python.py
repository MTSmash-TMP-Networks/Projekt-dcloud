"""Create/update config.yml for the native Windows Python installer."""
from __future__ import annotations

import os
import socket
from pathlib import Path

import yaml

GIB = 1024 ** 3


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


def read_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data if isinstance(data, dict) else {}


def write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False, allow_unicode=True)


def main() -> int:
    repo_root = Path(os.environ.get("DCLOUD_REPO_ROOT", ".")).resolve()
    data_dir = Path(os.environ.get("DCLOUD_WINDOWS_DATA_DIR", repo_root / "windows-data")).resolve()
    config_path = Path(os.environ.get("DCLOUD_CONFIG_FILE", data_dir / "config.yml")).resolve()
    default_config = repo_root / "dcloud_client" / "config.yml"

    created = not config_path.exists()
    raw = read_yaml(config_path if config_path.exists() else default_config)

    raw.setdefault("node", {})
    raw.setdefault("storage", {})
    raw.setdefault("web", {})
    raw.setdefault("network", {})
    raw.setdefault("smb", {})

    node_name = os.environ.get("DCLOUD_NODE_NAME")
    if not node_name:
        host = socket.gethostname().strip() or os.environ.get("COMPUTERNAME", "windows")
        node_name = f"dcloud-{host}"

    dashboard_port = as_int(os.environ.get("DCLOUD_DASHBOARD_PORT"), int(raw.get("web", {}).get("port", 8787)))
    udp_port = as_int(os.environ.get("DCLOUD_DISCOVERY_UDP_PORT"), int(raw.get("network", {}).get("udp_port", 6881)))
    storage_limit_gb = as_int(os.environ.get("DCLOUD_STORAGE_LIMIT_GB"), int(int(raw.get("storage", {}).get("limit_bytes", 50 * GIB)) / GIB) or 50)
    storage_limit_gb = max(5, storage_limit_gb)

    storage_path = Path(os.environ.get("DCLOUD_STORAGE_PATH", data_dir / "storage")).resolve()
    identity_path = Path(os.environ.get("DCLOUD_IDENTITY_PATH", storage_path / "identity")).resolve()
    storage_path.mkdir(parents=True, exist_ok=True)
    (storage_path / "web").mkdir(parents=True, exist_ok=True)
    (storage_path / "Downloads").mkdir(parents=True, exist_ok=True)
    identity_path.parent.mkdir(parents=True, exist_ok=True)

    raw["node"]["name"] = node_name
    raw["node"]["identity_path"] = str(identity_path)
    raw["node"]["client_type"] = "server"

    raw["storage"]["path"] = str(storage_path)
    raw["storage"]["limit_bytes"] = int(storage_limit_gb * GIB)
    raw["storage"].setdefault("min_free_bytes", 1 * GIB)
    raw["storage"].setdefault("chunk_size_bytes", 4 * 1024 * 1024)

    raw["web"]["host"] = os.environ.get("DCLOUD_WEB_HOST", "0.0.0.0")
    raw["web"]["port"] = dashboard_port

    raw["network"]["udp_host"] = os.environ.get("DCLOUD_UDP_HOST", "0.0.0.0")
    raw["network"]["udp_port"] = udp_port
    raw["network"]["udp_port_range"] = {"start": udp_port, "end": udp_port}
    raw["network"]["auto_discovery_ports"] = [udp_port]
    raw["network"].setdefault("auto_discovery_hosts", ["255.255.255.255"])

    # Native Windows usually already owns SMB port 445. Keep SMB off by default
    # unless the user explicitly enables it through an environment variable or later in the dashboard.
    if "DCLOUD_ENABLE_SMB" in os.environ:
        raw["smb"]["enabled"] = as_bool(os.environ.get("DCLOUD_ENABLE_SMB"), False)
    elif created:
        raw["smb"]["enabled"] = False
    raw["smb"].setdefault("host", "0.0.0.0")
    raw["smb"].setdefault("port", 445)
    raw["smb"].setdefault("share_name", "DCLOUD")
    raw["smb"].setdefault("username", "admin")
    raw["smb"].setdefault("password", "admin")

    write_yaml(config_path, raw)
    print(f"CONFIG={config_path}")
    print(f"NODE={node_name}")
    print(f"DASHBOARD_PORT={dashboard_port}")
    print(f"STORAGE={storage_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
