"""Configuration loading, persistence and validation for the dcloud client."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import os
import re
import shutil
import tempfile

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).parent / "data" / "default_config.yml"
VALID_CLIENT_TYPES = {"server"}
DEFAULT_CLIENT_TYPE = "server"
MIN_SHARED_STORAGE_GB = 5
GIB = 1024**3
DEFAULT_AUTO_DISCOVERY_PORTS = [6881]
DEFAULT_AUTO_DISCOVERY_HOSTS = ["255.255.255.255"]
DEFAULT_PEER_TIMEOUT_SECONDS = 35
DEFAULT_PEER_CLEANUP_INTERVAL_SECONDS = 5
DEFAULT_RELAY_POLL_INTERVAL_SECONDS = 0
DEFAULT_RELAY_REQUEST_TIMEOUT_SECONDS = 0
DEFAULT_RELAY_CHUNK_SIZE_BYTES = 0
DEFAULT_PUBLIC_RELAY_URL = ""
DEPRECATED_PUBLIC_RELAY_HOSTS = {"dcloud.byethost12.com"}
DEFAULT_PUBLIC_RELAY_URLS: list[str] = []
VALID_COMPRESSION_MODES = {"auto", "fast", "balanced", "max", "off"}
VALID_COMPRESSION_ALGORITHMS = {"auto", "zstd", "zlib", "none"}
DEFAULT_COMPRESSION_MODE = "auto"
DEFAULT_COMPRESSION_ALGORITHM = "zlib"
DEFAULT_COMPRESSION_LEVEL = 1
DEFAULT_COMPRESSION_MIN_SAVINGS_PERCENT = 3.0
DEFAULT_COMPRESSION_MIN_SAVINGS_BYTES = 64 * 1024



@dataclass
class NodeConfig:
    name: str
    identity_path: Path
    client_type: str = DEFAULT_CLIENT_TYPE


@dataclass
class CompressionConfig:
    mode: str = DEFAULT_COMPRESSION_MODE
    algorithm: str = DEFAULT_COMPRESSION_ALGORITHM
    level: int = DEFAULT_COMPRESSION_LEVEL
    min_savings_percent: float = DEFAULT_COMPRESSION_MIN_SAVINGS_PERCENT
    min_savings_bytes: int = DEFAULT_COMPRESSION_MIN_SAVINGS_BYTES
    skip_incompressible: bool = True


@dataclass
class StorageConfig:
    path: Path
    limit_bytes: int
    min_free_bytes: int
    chunk_size_bytes: int
    compression: CompressionConfig = field(default_factory=CompressionConfig)


@dataclass
class WebConfig:
    host: str
    port: int


@dataclass
class UdpPortRange:
    start: int
    end: int


@dataclass
class NetworkConfig:
    udp_host: str
    udp_port: int
    udp_port_range: UdpPortRange
    bootstrap_nodes: list[str] = field(default_factory=list)
    tree_parent_nodes: list[str] = field(default_factory=list)
    relay_children: bool = False
    discovery_interval_seconds: int = 10
    auto_discovery_enabled: bool = True
    auto_discovery_ports: list[int] = field(default_factory=lambda: DEFAULT_AUTO_DISCOVERY_PORTS.copy())
    auto_discovery_hosts: list[str] = field(default_factory=lambda: DEFAULT_AUTO_DISCOVERY_HOSTS.copy())
    startup_discovery_seconds: int = 12
    startup_discovery_interval_seconds: int = 2
    peer_timeout_seconds: int = DEFAULT_PEER_TIMEOUT_SECONDS
    peer_cleanup_interval_seconds: int = DEFAULT_PEER_CLEANUP_INTERVAL_SECONDS
    relay_url: str = ""
    relay_urls: list[str] = field(default_factory=list)
    relay_secret: str = ""  # legacy, ignored
    relay_poll_interval_seconds: float = DEFAULT_RELAY_POLL_INTERVAL_SECONDS
    relay_request_timeout_seconds: int = DEFAULT_RELAY_REQUEST_TIMEOUT_SECONDS
    relay_chunk_size_bytes: int = DEFAULT_RELAY_CHUNK_SIZE_BYTES


@dataclass
class SecurityConfig:
    protocol_magic: str


@dataclass
class SmbConfig:
    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 445
    share_name: str = "DCLOUD"
    username: str = ""
    password: str = ""


@dataclass
class AppConfig:
    node: NodeConfig
    storage: StorageConfig
    web: WebConfig
    network: NetworkConfig
    security: SecurityConfig
    config_path: Path
    smb: SmbConfig = field(default_factory=SmbConfig)


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge two dictionaries without mutating the inputs."""
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Configuration file {path} must contain a YAML mapping")
    return data


def _write_yaml_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix="config-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            yaml.safe_dump(data, handle, sort_keys=False, allow_unicode=True)
            handle.flush()
        Path(tmp_name).replace(path)
    except Exception:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def normalize_client_type(value: str | None) -> str:
    _ = value
    return "server"


def client_type_label(client_type: str) -> str:
    _ = client_type
    return "Server"


def bytes_to_gib(value: int) -> float:
    return round(int(value) / GIB, 2)


def gib_to_bytes(value: float | int | str) -> int:
    return int(round(float(value) * GIB))


def validate_shared_storage_bytes(value: int) -> int:
    value = int(value)
    minimum = MIN_SHARED_STORAGE_GB * GIB
    if value < minimum:
        raise ValueError(f"Mindestens {MIN_SHARED_STORAGE_GB} GB müssen freigegeben werden")
    return value


def normalize_compression_mode(value: Any) -> str:
    mode = str(value or DEFAULT_COMPRESSION_MODE).strip().lower()
    if mode not in VALID_COMPRESSION_MODES:
        raise ValueError("Komprimierungsmodus muss auto, fast, balanced, max oder off sein")
    return mode


def normalize_compression_algorithm(value: Any) -> str:
    algorithm = str(value or DEFAULT_COMPRESSION_ALGORITHM).strip().lower()
    if algorithm not in VALID_COMPRESSION_ALGORITHMS:
        raise ValueError("Komprimierungsalgorithmus muss auto, zstd, zlib oder none sein")
    return algorithm


def normalize_compression_level(value: Any, mode: str = DEFAULT_COMPRESSION_MODE) -> int:
    if value in {None, ""}:
        return {"fast": 1, "balanced": 3, "max": 10}.get(mode, DEFAULT_COMPRESSION_LEVEL)
    return max(1, min(22, int(value)))


def normalize_min_savings_percent(value: Any) -> float:
    return max(0.0, min(30.0, float(value if value not in {None, ""} else DEFAULT_COMPRESSION_MIN_SAVINGS_PERCENT)))


def normalize_min_savings_bytes(value: Any) -> int:
    return max(0, min(16 * 1024 * 1024, int(value if value not in {None, ""} else DEFAULT_COMPRESSION_MIN_SAVINGS_BYTES)))


def _as_list(value: Any, default: list[Any]) -> list[Any]:
    if value is None:
        return list(default)
    if isinstance(value, list):
        return value
    return [value]


def normalize_ports(values: Any, default: list[int] | None = None) -> list[int]:
    result: list[int] = []
    for raw in _as_list(values, default or DEFAULT_AUTO_DISCOVERY_PORTS):
        port = int(raw)
        if not 1 <= port <= 65535:
            raise ValueError("Discovery-Ports müssen zwischen 1 und 65535 liegen")
        if port not in result:
            result.append(port)
    return result


def normalize_hosts(values: Any, default: list[str] | None = None) -> list[str]:
    result: list[str] = []
    for raw in _as_list(values, default or DEFAULT_AUTO_DISCOVERY_HOSTS):
        host = str(raw).strip()
        if not host:
            continue
        if host not in result:
            result.append(host)
    return result or list(default or DEFAULT_AUTO_DISCOVERY_HOSTS)


def normalize_relay_url(value: str | None) -> str:
    url = (value or "").strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        raise ValueError("Direkter Peer-Endpunkt muss mit http:// oder https:// beginnen")
    return url.rstrip("/")


def _iter_relay_url_candidates(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        result: list[str] = []
        for item in value:
            result.extend(_iter_relay_url_candidates(item))
        return result
    text = str(value)
    # Settings use a textarea; configs may use YAML lists. Also accept comma or
    # semicolon separated values for quick copy/paste.
    return [item for item in re.split(r"[\s,;]+", text) if item.strip()]


def is_deprecated_relay_url(url: str) -> bool:
    normalized = normalize_relay_url(url).lower()
    match = re.match(r"^https?://([^/:]+)", normalized)
    host = match.group(1) if match else ""
    return host in DEPRECATED_PUBLIC_RELAY_HOSTS


def normalize_relay_urls(values: Any, *, include_default: bool = True) -> list[str]:
    result: list[str] = []
    if include_default:
        result.extend(DEFAULT_PUBLIC_RELAY_URLS)
    for raw in _iter_relay_url_candidates(values):
        url = normalize_relay_url(raw)
        if not url or is_deprecated_relay_url(url):
            continue
        if url not in result:
            result.append(url)
    return result


def extra_relay_urls(values: Any) -> list[str]:
    fixed_relays = set(DEFAULT_PUBLIC_RELAY_URLS)
    return [url for url in normalize_relay_urls(values, include_default=True) if url not in fixed_relays]


def normalize_relay_secret(value: str | None) -> str:
    return (value or "").strip()


def ensure_config(config_path: Path) -> None:
    """Create a starter config file if none exists yet."""
    if config_path.exists():
        return
    config_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(DEFAULT_CONFIG_PATH, config_path)


def load_config(config_path: str | Path = "config.yml", *, create_if_missing: bool = True) -> AppConfig:
    """Load config.yml merged over built-in defaults."""
    path = Path(config_path).expanduser().resolve()
    if create_if_missing:
        ensure_config(path)

    raw = deep_merge(_load_yaml(DEFAULT_CONFIG_PATH), _load_yaml(path))
    base_dir = path.parent

    node_raw = raw.get("node", {})
    storage_raw = raw.get("storage", {})
    web_raw = raw.get("web", {})
    network_raw = raw.get("network", {})
    security_raw = raw.get("security", {})

    def as_path(value: str) -> Path:
        candidate = Path(value).expanduser()
        return candidate if candidate.is_absolute() else (base_dir / candidate).resolve()

    compression_raw = storage_raw.get("compression", {})
    if not isinstance(compression_raw, dict):
        compression_raw = {}
    compression_mode = normalize_compression_mode(compression_raw.get("mode", DEFAULT_COMPRESSION_MODE))
    compression = CompressionConfig(
        mode=compression_mode,
        algorithm=normalize_compression_algorithm(compression_raw.get("algorithm", DEFAULT_COMPRESSION_ALGORITHM)),
        level=normalize_compression_level(compression_raw.get("level", ""), compression_mode),
        min_savings_percent=normalize_min_savings_percent(compression_raw.get("min_savings_percent", DEFAULT_COMPRESSION_MIN_SAVINGS_PERCENT)),
        min_savings_bytes=normalize_min_savings_bytes(compression_raw.get("min_savings_bytes", DEFAULT_COMPRESSION_MIN_SAVINGS_BYTES)),
        skip_incompressible=bool(compression_raw.get("skip_incompressible", True)),
    )

    storage = StorageConfig(
        path=as_path(str(storage_raw.get("path", "./storage"))),
        limit_bytes=int(storage_raw.get("limit_bytes", 50 * GIB)),
        min_free_bytes=int(storage_raw.get("min_free_bytes", 1 * GIB)),
        chunk_size_bytes=int(storage_raw.get("chunk_size_bytes", 4 * 1024**2)),
        compression=compression,
    )
    if storage.limit_bytes <= 0 or storage.chunk_size_bytes <= 0:
        raise ValueError("Storage limit and chunk size must be positive")

    port_range_raw = network_raw.get("udp_port_range", {})
    udp_range = UdpPortRange(
        start=int(port_range_raw.get("start", 6881)),
        end=int(port_range_raw.get("end", 6891)),
    )
    if udp_range.start > udp_range.end:
        raise ValueError("network.udp_port_range.start must be <= end")

    # PHP relay support was removed. Ignore old relay_url/relay_urls keys.
    relay_urls_loaded: list[str] = []
    relay_primary_url = relay_urls_loaded[0] if relay_urls_loaded else ""

    return AppConfig(
        node=NodeConfig(
            name=str(node_raw.get("name", "dcloud-node")),
            identity_path=as_path(str(node_raw.get("identity_path", storage.path / "identity"))),
            client_type=normalize_client_type(str(node_raw.get("client_type", DEFAULT_CLIENT_TYPE))),
        ),
        storage=storage,
        web=WebConfig(host=str(web_raw.get("host", "127.0.0.1")), port=int(web_raw.get("port", 8787))),
        network=NetworkConfig(
            udp_host=str(network_raw.get("udp_host", "0.0.0.0")),
            udp_port=int(network_raw.get("udp_port", 6881)),
            udp_port_range=udp_range,
            bootstrap_nodes=list(network_raw.get("bootstrap_nodes", [])),
            tree_parent_nodes=list(network_raw.get("tree_parent_nodes", [])),
            relay_children=bool(network_raw.get("relay_children", False)),
            discovery_interval_seconds=max(1, int(network_raw.get("discovery_interval_seconds", 10))),
            auto_discovery_enabled=bool(network_raw.get("auto_discovery_enabled", True)),
            auto_discovery_ports=normalize_ports(network_raw.get("auto_discovery_ports"), DEFAULT_AUTO_DISCOVERY_PORTS),
            auto_discovery_hosts=normalize_hosts(network_raw.get("auto_discovery_hosts"), DEFAULT_AUTO_DISCOVERY_HOSTS),
            startup_discovery_seconds=max(0, int(network_raw.get("startup_discovery_seconds", 12))),
            startup_discovery_interval_seconds=max(1, int(network_raw.get("startup_discovery_interval_seconds", 2))),
            peer_timeout_seconds=max(5, int(network_raw.get("peer_timeout_seconds", DEFAULT_PEER_TIMEOUT_SECONDS))),
            peer_cleanup_interval_seconds=max(1, int(network_raw.get("peer_cleanup_interval_seconds", DEFAULT_PEER_CLEANUP_INTERVAL_SECONDS))),
            relay_url=relay_primary_url,
            relay_urls=relay_urls_loaded,
            relay_secret=normalize_relay_secret(str(network_raw.get("relay_secret", ""))),
            relay_poll_interval_seconds=max(0.2, float(network_raw.get("relay_poll_interval_seconds", DEFAULT_RELAY_POLL_INTERVAL_SECONDS))),
            relay_request_timeout_seconds=max(30, int(network_raw.get("relay_request_timeout_seconds", DEFAULT_RELAY_REQUEST_TIMEOUT_SECONDS))),
            relay_chunk_size_bytes=max(64 * 1024, min(int(network_raw.get("relay_chunk_size_bytes", DEFAULT_RELAY_CHUNK_SIZE_BYTES)), 2 * 1024 * 1024)),
        ),
        security=SecurityConfig(protocol_magic=str(security_raw.get("protocol_magic", "DCLOUD1"))),
        smb=SmbConfig(
            enabled=bool(raw.get("smb", {}).get("enabled", False)),
            host=str(raw.get("smb", {}).get("host", "0.0.0.0")),
            port=int(raw.get("smb", {}).get("port", 445)),
            share_name=str(raw.get("smb", {}).get("share_name", "DCLOUD")).strip() or "DCLOUD",
            username=str(raw.get("smb", {}).get("username", "")).strip(),
            password=str(raw.get("smb", {}).get("password", "")),
        ),
        config_path=path,
    )


def persist_relay_urls(config: AppConfig, relay_urls: list[str]) -> AppConfig:
    """Persist the fixed public relay plus known additional relay URLs."""
    normalized_relay_urls = []
    raw = _load_yaml(config.config_path)
    raw.setdefault("network", {})
    if not isinstance(raw["network"], dict):
        raise ValueError("Konfigurationsdatei hat kein gültiges network Mapping")
    raw["network"]["relay_url"] = ""
    raw["network"]["relay_urls"] = []
    _write_yaml_atomic(config.config_path, raw)
    config.network.relay_url = normalized_relay_urls[0]
    config.network.relay_urls = normalized_relay_urls
    return config


def update_runtime_settings(
    config: AppConfig,
    *,
    client_type: str,
    shared_storage_gb: float | int | str,
    relay_server_url: str | None = None,
    relay_server_urls: Any | None = None,
    relay_enabled: bool | str | int | None = None,
    relay_secret: str | None = None,
    smb_enabled: bool | str | int | None = None,
    smb_username: str | None = None,
    smb_password: str | None = None,
    compression_mode: str | None = None,
    compression_algorithm: str | None = None,
    compression_level: str | int | None = None,
    compression_min_savings_percent: str | float | None = None,
    compression_skip_incompressible: bool | str | int | None = None,
) -> AppConfig:
    """Persist editable desktop settings and update the live config object."""
    normalized_type = normalize_client_type(client_type)
    storage_limit_bytes = validate_shared_storage_bytes(gib_to_bytes(shared_storage_gb))
    new_compression_mode = normalize_compression_mode(compression_mode if compression_mode is not None else config.storage.compression.mode)
    new_compression_algorithm = normalize_compression_algorithm(compression_algorithm if compression_algorithm is not None else config.storage.compression.algorithm)
    new_compression_level = normalize_compression_level(compression_level if compression_level is not None else config.storage.compression.level, new_compression_mode)
    new_min_savings_percent = normalize_min_savings_percent(
        compression_min_savings_percent if compression_min_savings_percent is not None else config.storage.compression.min_savings_percent
    )
    new_skip_incompressible = (
        bool(compression_skip_incompressible)
        if compression_skip_incompressible is not None
        else config.storage.compression.skip_incompressible
    )
    relay_values = relay_server_urls if relay_server_urls is not None else relay_server_url
    relay_is_enabled = False
    if relay_is_enabled:
        normalized_relay_urls = (
            normalize_relay_urls(relay_values, include_default=True)
            if relay_values is not None
            else normalize_relay_urls(config.network.relay_urls, include_default=True)
        )
    else:
        # When the checkbox is off, the textarea can be disabled and omitted
        # from FormData. Treat the checkbox as authoritative and clear all
        # relay URLs instead of preserving stale values.
        normalized_relay_urls = []
    # Relay access tokens are generated automatically by each PHP relay and
    # refreshed daily by the client. Manual relay_secret values from older
    # configs are cleared on the next settings save.
    normalized_relay_secret = ""

    raw = _load_yaml(config.config_path)
    raw.setdefault("node", {})
    raw.setdefault("storage", {})
    raw.setdefault("network", {})
    raw.setdefault("smb", {})
    if not isinstance(raw["node"], dict) or not isinstance(raw["storage"], dict) or not isinstance(raw["network"], dict):
        raise ValueError("Konfigurationsdatei hat kein gültiges node/storage/network Mapping")
    if not isinstance(raw["smb"], dict):
        raise ValueError("Konfigurationsdatei hat kein gültiges smb Mapping")

    raw["node"]["client_type"] = normalized_type
    raw["storage"]["limit_bytes"] = storage_limit_bytes
    raw["storage"]["compression"] = {
        "mode": new_compression_mode,
        "algorithm": new_compression_algorithm,
        "level": new_compression_level,
        "min_savings_percent": new_min_savings_percent,
        "min_savings_bytes": config.storage.compression.min_savings_bytes,
        "skip_incompressible": new_skip_incompressible,
    }
    raw["network"]["relay_url"] = ""
    raw["network"]["relay_urls"] = []
    raw["network"]["relay_secret"] = normalized_relay_secret
    raw["smb"]["enabled"] = bool(smb_enabled) if smb_enabled is not None else config.smb.enabled
    raw["smb"]["username"] = (smb_username if smb_username is not None else config.smb.username).strip()
    raw["smb"]["password"] = smb_password if smb_password is not None else config.smb.password
    _write_yaml_atomic(config.config_path, raw)

    config.node.client_type = normalized_type
    config.storage.limit_bytes = storage_limit_bytes
    config.storage.compression = CompressionConfig(
        mode=new_compression_mode,
        algorithm=new_compression_algorithm,
        level=new_compression_level,
        min_savings_percent=new_min_savings_percent,
        min_savings_bytes=config.storage.compression.min_savings_bytes,
        skip_incompressible=new_skip_incompressible,
    )
    config.network.relay_url = ""
    config.network.relay_urls = []
    config.network.relay_secret = normalized_relay_secret
    config.smb.enabled = bool(smb_enabled) if smb_enabled is not None else config.smb.enabled
    config.smb.username = (smb_username if smb_username is not None else config.smb.username).strip()
    config.smb.password = smb_password if smb_password is not None else config.smb.password
    return config
