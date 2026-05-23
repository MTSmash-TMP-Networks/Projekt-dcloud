"""Flask application for the local-only MVP web UI."""

from __future__ import annotations

from pathlib import Path
import tempfile
from typing import Any, Protocol
from io import BytesIO
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from uuid import uuid4
import atexit
import base64
import socket
import time
import subprocess

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename
try:
    from smb.SMBConnection import SMBConnection
except ImportError:
    SMBConnection = None


from ..config import (
    AppConfig,
    DEFAULT_PUBLIC_RELAY_URL,
    MIN_SHARED_STORAGE_GB,
    bytes_to_gib,
    client_type_label,
    extra_relay_urls,
    normalize_relay_urls,
    persist_relay_urls,
    update_runtime_settings,
)
from ..identity import NodeIdentity
from ..manifests import DEFAULT_FOLDER, FileManifest, ManifestStore, sanitize_folder_path
from ..network.http_relay import HttpRelayClient, HttpRelayTransport, RelayHttpResponse, RELAY_HOST
from ..network.p2p_storage import (
    P2PStorageClient,
    build_manifest_deletion,
    build_manifest_revocation,
    distribute_file_chunks,
    verify_manifest_deletion,
    verify_manifest_revocation,
)
from ..network.peers import PeerProvider, display_name_for_peer
from ..storage import ChunkStore, StorageError, StorageStats
from .upload_progress import UploadProgressTracker


class PeerConnector(Protocol):
    def add_peer_address(self, host: str, port: int, *, use_as_tree_parent: bool = False) -> None: ...
    def announce_once(self) -> None: ...
    def prune_stale_peers(self) -> list[str]: ...


def human_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{value} B"




def current_git_revision() -> str:
    try:
        result = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True)
        revision = result.stdout.strip()
        return revision or "unbekannt"
    except Exception:
        return "unbekannt"

def _tail_text_file(path: Path, *, max_lines: int = 120, max_chars: int = 12000) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
        text = "".join(lines[-max_lines:])
        return text[-max_chars:] if len(text) > max_chars else text
    except Exception:
        return ""


def build_folder_tree(manifests: list[FileManifest], folders: list[str] | None = None) -> list[dict[str, object]]:
    """Group manifests into user-created virtual folders."""
    grouped: dict[str, list[FileManifest]] = {folder: [] for folder in (folders or [DEFAULT_FOLDER])}
    for manifest in manifests:
        grouped.setdefault(manifest.folder_path, []).append(manifest)
    return [
        {"name": folder, "files": sorted(files, key=lambda item: item.file_name.lower())}
        for folder, files in sorted(grouped.items(), key=lambda item: item[0].lower())
    ]


def create_app(
    config: AppConfig,
    identity: NodeIdentity,
    chunk_store: ChunkStore,
    manifest_store: ManifestStore,
    peer_provider: PeerProvider,
    peer_connector: PeerConnector | None = None,
    runtime_udp_port: int | None = None,
) -> Flask:
    app = Flask(__name__)
    app.secret_key = identity.node_id[:32]
    active_udp_port = int(runtime_udp_port if runtime_udp_port is not None else config.network.udp_port)
    app.config["DCLOUD_APP_CONFIG"] = config
    app.jinja_env.filters["human_bytes"] = human_bytes
    relay_clients: dict[str, HttpRelayClient] = {}
    relay_transports: dict[str, HttpRelayTransport] = {}
    relay_lock = threading.RLock()
    def _handle_udp_chunk_message(message: dict[str, Any], _address: tuple[str, int]) -> dict[str, Any] | None:
        if message.get("type") != "chunk_put":
            return None
        try:
            digest = str(message.get("digest", ""))
            stored_data = base64.b64decode(str(message.get("data_b64", "")).encode("ascii"), validate=True)
            original_size = int(message.get("original_size", 0))
            index = int(message.get("index", 0))
            compression = str(message.get("compression") or "") or None
            chunk_store.write_stored_chunk(digest=digest, stored_data=stored_data, original_size=original_size, index=index, compression=compression)
            return {"ok": True, "digest": digest}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    def _send_udp_chunk_message(peer: Peer, payload: dict[str, Any]) -> dict[str, Any] | None:
        if peer.host in {"", "0.0.0.0", "::", "__relay__"}:
            return None
        msg = dict(payload)
        msg["magic"] = config.security.protocol_magic
        msg["node_id"] = identity.node_id
        msg["public_key"] = identity.public_key_b64
        msg["name"] = config.node.name
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.8)
            sock.bind((config.network.udp_host, 0))
            msg["udp_port"] = int(sock.getsockname()[1])
            sock.sendto(json.dumps(msg, separators=(",", ":")).encode("utf-8"), (peer.host, int(peer.udp_port)))
            raw, _ = sock.recvfrom(65535)
        response = json.loads(raw.decode("utf-8"))
        if response.get("magic") != config.security.protocol_magic or response.get("type") != "chunk_put_ack":
            return None
        return response

    p2p_client = P2PStorageClient(
        default_web_port=config.web.port,
        preferred_tunnel_ports=config.network.preferred_tunnel_ports,
        udp_chunk_sender=_send_udp_chunk_message,
    )
    if peer_connector is not None and hasattr(peer_connector, "set_chunk_message_handler"):
        peer_connector.set_chunk_message_handler(_handle_udp_chunk_message)
    upload_progress = UploadProgressTracker(persist_dir=chunk_store.tmp_dir / "upload_progress")
    chat_messages: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=120))
    replication_repair_lock = threading.Lock()
    last_replication_repair_at = 0.0

    def _recover_peer_via_relay(stale_peer: Peer) -> Peer | None:
        """If a peer dropped from active list, refresh relay view and return it again."""
        with relay_lock:
            transports = list(relay_transports.values())
        for transport in transports:
            try:
                transport._register_and_ingest_peers()  # noqa: SLF001 - intentional best-effort recovery hook
            except Exception:
                continue
            recovered = peer_provider.get_peer(stale_peer.node_id)
            if recovered is not None:
                return recovered
        return peer_provider.get_peer(stale_peer.node_id)

    p2p_client.peer_recovery_callback = _recover_peer_via_relay

    def _is_ajax_request() -> bool:
        return request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.accept_mimetypes.best == "application/json"

    def _safe_upload_id(value: str | None) -> str:
        cleaned = "".join(char for char in (value or "") if char.isalnum() or char in "-_")[:80]
        return cleaned or uuid4().hex

    def _cleanup_storage_garbage(*, stale_tmp_age_seconds: int = 900) -> dict[str, int]:
        referenced_chunks = {
            str(chunk["hash"])
            for manifest in manifest_store.list_manifests()
            for chunk in manifest.chunks
        }
        removed_unreferenced_chunks = 0
        removed_stale_tmp_files = 0
        removed_empty_chunk_dirs = 0
        now = datetime.now(timezone.utc).timestamp()

        for chunk_path in chunk_store.chunks_dir.glob("*/*.chunk"):
            digest = chunk_path.stem
            if digest in referenced_chunks:
                continue
            chunk_path.unlink(missing_ok=True)
            removed_unreferenced_chunks += 1

        for tmp_path in chunk_store.tmp_dir.glob("*"):
            if not tmp_path.is_file():
                continue
            try:
                age_seconds = now - tmp_path.stat().st_mtime
            except OSError:
                continue
            if age_seconds < stale_tmp_age_seconds:
                continue
            tmp_path.unlink(missing_ok=True)
            removed_stale_tmp_files += 1

        for chunk_dir in chunk_store.chunks_dir.glob("*"):
            if not chunk_dir.is_dir():
                continue
            try:
                chunk_dir.rmdir()
                removed_empty_chunk_dirs += 1
            except OSError:
                continue

        return {
            "removed_unreferenced_chunks": removed_unreferenced_chunks,
            "removed_stale_tmp_files": removed_stale_tmp_files,
            "removed_empty_chunk_dirs": removed_empty_chunk_dirs,
        }

    def _upload_server_progress(upload_id: str):
        def handle(event: dict[str, Any]) -> None:
            total_chunks = int(event.get("total_chunks") or 0)
            current_chunk = int(event.get("current_chunk") or 0)
            phase = str(event.get("phase") or "processing")
            phase_offset = {
                "chunk_read": 0.05,
                "chunk_compressed": 0.35,
                "local_store": 0.55,
                "peer_upload": 0.62,
                "peer_upload_failed": 0.72,
                "peer_upload_done": 0.82,
                "local_store_done": 0.86,
                "local_fallback": 0.74,
                "chunk_done": 1.0,
            }.get(phase, 0.15)
            if phase == "chunking_start":
                server_percent = 5.0
            elif phase == "chunking_done":
                server_percent = 96.0
            elif total_chunks > 0 and current_chunk > 0:
                completed_before = max(0, min(total_chunks, current_chunk - 1))
                chunk_fraction = min(1.0, (completed_before + phase_offset) / total_chunks)
                server_percent = 5.0 + chunk_fraction * 90.0
            else:
                server_percent = 8.0
            overall_percent = min(99.0, 40.0 + server_percent * 0.59)
            allowed = {
                "phase",
                "status",
                "total_bytes",
                "raw_bytes_processed",
                "stored_bytes",
                "current_chunk",
                "total_chunks",
                "compressed_chunks",
                "local_chunks",
                "remote_successes",
                "remote_failures",
                "desired_replicas",
                "target_count",
                "current_peer",
            }
            fields = {key: value for key, value in event.items() if key in allowed}
            fields["server_percent"] = server_percent
            fields["percent"] = overall_percent
            upload_progress.update(upload_id, **fields)

        return handle

    def _safe_next(value: str | None, fallback: str) -> str:
        allowed = {url_for("dashboard"), url_for("files")}
        return value if value in allowed else fallback

    def _list_active_peers() -> list[Any]:
        if peer_connector is not None and hasattr(peer_connector, "prune_stale_peers"):
            peer_connector.prune_stale_peers()
        return peer_provider.list_peers()

    def stats_payload(stats: StorageStats) -> dict[str, int | str]:
        smb_root_path = str(app.config.get("DCLOUD_SMB_ROOT") or config.storage.path)
        return {
            "path": str(stats.path),
            "limitBytes": stats.limit_bytes,
            "usedBytes": stats.used_bytes,
            "freeLimitBytes": stats.free_limit_bytes,
            "filesystemFreeBytes": stats.filesystem_free_bytes,
            "minFreeBytes": stats.min_free_bytes,
        }

    def _accepts_peer_storage(peers: list[Any]) -> bool:
        _ = peers
        return not bool(getattr(config.network, "outgoing_only", False))

    def _storage_policy_message(peers: list[Any]) -> str:
        _ = peers
        return "Server-Modus: Dieser Client arbeitet immer als Speicherziel-Knoten für P2P-Daten."

    def _eligible_storage_peers(peers: list[Any] | None = None) -> list[Any]:
        peers = peers if peers is not None else _list_active_peers()
        targets: list[Any] = []
        for peer in peers:
            # Unified server logic: all visible peers are valid storage targets.
            targets.append(peer)
        seen: set[str] = set()
        unique: list[Any] = []
        for peer in targets:
            if peer.node_id in seen:
                continue
            seen.add(peer.node_id)
            unique.append(peer)
        return unique

    def _eligible_storage_peer_node_ids() -> list[str]:
        return [peer.node_id for peer in _eligible_storage_peers()]

    def _reject_if_outgoing_only() -> Response | None:
        if bool(getattr(config.network, "outgoing_only", False)):
            return jsonify({"ok": False, "message": "Outgoing-Only aktiv: eingehende Peer-Verbindungen sind deaktiviert.", "state": state_payload()}), 403
        return None

    def _repair_under_replicated_manifests(peers: list[Any] | None = None, *, min_interval_seconds: float = 20.0) -> None:
        """Best-effort healing for chunks that temporarily lost remote replicas."""
        nonlocal last_replication_repair_at
        now = time.monotonic()
        if now - last_replication_repair_at < max(1.0, float(min_interval_seconds)):
            return
        if not replication_repair_lock.acquire(blocking=False):
            return
        try:
            last_replication_repair_at = now
            active_peers = _eligible_storage_peers(peers)
            peers_by_id = {peer.node_id: peer for peer in active_peers}
            if not peers_by_id:
                return
            for manifest in manifest_store.list_manifests():
                if manifest.owner_node_id != identity.node_id:
                    continue
                manifest_changed = False
                for chunk in manifest.chunks:
                    existing_locations = [str(node_id) for node_id in chunk.get("locations", []) if str(node_id)]
                    remote_locations = [node_id for node_id in existing_locations if node_id != identity.node_id]
                    if remote_locations:
                        continue
                    digest = str(chunk.get("hash", ""))
                    if not digest:
                        continue
                    try:
                        stored_data = chunk_store.read_stored_chunk(digest)
                    except StorageError:
                        continue
                    for peer_id, peer in peers_by_id.items():
                        transfer = p2p_client.put_chunk(
                            peer,
                            digest=digest,
                            stored_data=stored_data,
                            original_size=int(chunk.get("size", len(stored_data))),
                            stored_size=int(chunk.get("stored_size", len(stored_data))),
                            index=int(chunk.get("index", 0)),
                            compression=str(chunk.get("compression")) if chunk.get("compression") else None,
                        )
                        if transfer.ok:
                            chunk["locations"] = list(dict.fromkeys([*existing_locations, peer_id]))
                            manifest_changed = True
                            break
                if manifest_changed:
                    manifest_store.update_placement(
                        manifest.manifest_id,
                        identity,
                        chunks=manifest.chunks,
                        placement=dict(manifest.placement or {}),
                    )
        finally:
            replication_repair_lock.release()

    def _network_storage_capacity(stats: StorageStats, peers: list[Any]) -> dict[str, int]:
        eligible = _eligible_storage_peers(peers)
        remote_total = sum(int(getattr(peer, "shared_storage_bytes", 0) or 0) for peer in eligible)
        remote_free = sum(
            int(getattr(peer, "free_storage_bytes", None) if getattr(peer, "free_storage_bytes", None) is not None else getattr(peer, "shared_storage_bytes", 0) or 0)
            for peer in eligible
        )
        return {
            "localLimitBytes": stats.limit_bytes,
            "localFreeBytes": stats.free_limit_bytes,
            "remoteLimitBytes": remote_total,
            "remoteFreeBytes": remote_free,
            "networkLimitBytes": stats.limit_bytes + remote_total,
            "networkFreeBytes": stats.free_limit_bytes + remote_free,
            "storagePeerCount": len(eligible),
        }

    def settings_payload(stats: StorageStats | None = None, peers: list[Any] | None = None) -> dict[str, Any]:
        current_stats = stats or chunk_store.stats()
        current_peers = peers if peers is not None else _list_active_peers()
        capacity = _network_storage_capacity(current_stats, current_peers)
        smb_server = app.config.get("DCLOUD_SMB_SERVER")
        runtime_smb_running = bool(getattr(smb_server, "running", False)) if smb_server is not None else bool(config.smb.enabled)
        runtime_smb_port = int(getattr(smb_server, "actual_port", config.smb.port)) if smb_server is not None else int(config.smb.port)
        runtime_smb_error = str(getattr(smb_server, "last_error", "") or "")
        smb_root_path = str(app.config.get("DCLOUD_SMB_ROOT") or config.storage.path)
        if config.smb.enabled and not runtime_smb_running and not runtime_smb_error:
            runtime_smb_error = (
                "SMB-Server läuft nicht. Prüfe Logausgabe, Port-Freigabe und ob der Speicherpfad verfügbar ist."
            )
        return {
            "nodeName": config.node.name,
            "nodeDisplayName": display_name_for_peer(identity.node_id, config.node.name),
            "clientType": config.node.client_type,
            "clientTypeLabel": client_type_label(config.node.client_type),
            "acceptsPeerStorage": _accepts_peer_storage(current_peers),
            "storagePolicy": _storage_policy_message(current_peers),
            "sharedStorageGb": bytes_to_gib(config.storage.limit_bytes),
            "minSharedStorageGb": MIN_SHARED_STORAGE_GB,
            "sharedStorageBytes": config.storage.limit_bytes,
            "freeSharedStorageBytes": current_stats.free_limit_bytes,
            "fixedRelayUrl": DEFAULT_PUBLIC_RELAY_URL,
            "relayUrl": config.network.relay_url,
            "relayUrls": list(config.network.relay_urls),
            "additionalRelayUrls": extra_relay_urls(config.network.relay_urls),
            "additionalRelayUrlsText": "\n".join(extra_relay_urls(config.network.relay_urls)),
            "relayEnabled": bool(config.network.relay_urls),
            "relaySecret": "",
            "relaySecretSet": False,
            "relayTokenMode": "automatic-daily",
            "relayTokenLabel": "Automatisch, tägliche Rotation",
            "dhtEnabled": bool(getattr(config.network, "dht_enabled", False)),
            "dhtK": int(getattr(config.network, "dht_k", 20)),
            "randomizeUdpPort": bool(getattr(config.network, "randomize_udp_port", True)),
            "upnpEnabled": bool(getattr(config.network, "upnp_enabled", False)),
            "natPmpEnabled": bool(getattr(config.network, "nat_pmp_enabled", False)),
            "preferredTunnelPortsText": ", ".join(str(port) for port in getattr(config.network, "preferred_tunnel_ports", [443, 80])),
            "outgoingOnly": bool(getattr(config.network, "outgoing_only", False)),
            "smbEnabled": bool(config.smb.enabled),
            "smbHost": config.smb.host,
            "smbPort": runtime_smb_port,
            "smbUsername": config.smb.username,
            "smbPasswordSet": bool(config.smb.password),
            "smbRunning": runtime_smb_running,
            "smbLastError": runtime_smb_error,
            "smbRootPath": smb_root_path,
            **capacity,
        }

    def _relay_url_list() -> list[str]:
        return normalize_relay_urls(getattr(config.network, "relay_urls", [config.network.relay_url]), include_default=False)

    def _relay_statuses() -> list[dict[str, Any]]:
        statuses: list[dict[str, Any]] = []
        for url in _relay_url_list():
            transport = relay_transports.get(url)
            if transport is None:
                status = "startet"
                last_error = None
            elif transport.last_error:
                status = "fehler"
                last_error = transport.last_error
            elif transport.last_success_at:
                status = "verbunden"
                last_error = None
            else:
                status = "startet"
                last_error = None
            client = relay_clients.get(url)
            statuses.append({
                "url": url,
                "fixed": url == DEFAULT_PUBLIC_RELAY_URL,
                "status": status,
                "lastError": last_error,
                "tokenMode": "automatic-daily",
                "tokenDay": getattr(client, "access_token_day", "") if client is not None else "",
                "tokenExpiresAt": getattr(client, "access_token_expires_at", None) if client is not None else None,
            })
        return statuses

    def _relay_overall_status(statuses: list[dict[str, Any]]) -> tuple[str, str | None]:
        if not statuses:
            return "aus", None
        if any(item.get("status") == "verbunden" for item in statuses):
            return "verbunden", None
        errors = [str(item.get("lastError")) for item in statuses if item.get("lastError")]
        if errors:
            return "fehler", "; ".join(errors[:2])
        return "startet", None

    def network_payload() -> dict[str, Any]:
        relay_statuses = _relay_statuses()
        relay_status, relay_error = _relay_overall_status(relay_statuses)
        active_peers = _list_active_peers()
        direct_peers = [
            peer for peer in active_peers
            if str(getattr(peer, "host", "")) not in {"", "__relay__"}
        ]
        relay_route_peers = [
            peer for peer in active_peers
            if str(getattr(peer, "host", "")) == "__relay__"
            or bool(getattr(peer, "relay_url", ""))
        ]
        return {
            "udpHost": config.network.udp_host,
            "udpPort": active_udp_port,
            "autoDiscoveryEnabled": config.network.auto_discovery_enabled,
            "autoDiscoveryPorts": config.network.auto_discovery_ports,
            "autoDiscoveryHosts": config.network.auto_discovery_hosts,
            "discoveryIntervalSeconds": config.network.discovery_interval_seconds,
            "startupDiscoverySeconds": config.network.startup_discovery_seconds,
            "startupDiscoveryIntervalSeconds": config.network.startup_discovery_interval_seconds,
            "peerTimeoutSeconds": getattr(config.network, "peer_timeout_seconds", 35),
            "peerCleanupIntervalSeconds": getattr(config.network, "peer_cleanup_interval_seconds", 5),
            "fixedRelayUrl": DEFAULT_PUBLIC_RELAY_URL,
            "relayUrl": config.network.relay_url,
            "relayUrls": _relay_url_list(),
            "additionalRelayUrls": extra_relay_urls(config.network.relay_urls),
            "relayEnabled": bool(_relay_url_list()),
            "relayPollIntervalSeconds": getattr(config.network, "relay_poll_interval_seconds", 1),
            "relayRequestTimeoutSeconds": getattr(config.network, "relay_request_timeout_seconds", 90),
            "relayStatus": relay_status,
            "relayLastError": relay_error,
            "relayStatuses": relay_statuses,
            "relayTokenMode": "automatic-daily",
            "directPeerCount": len(direct_peers),
            "relayRoutePeerCount": len(relay_route_peers),
            "relayBootstrapOnly": bool(direct_peers) and not bool(relay_route_peers),
            "dhtEnabled": bool(getattr(config.network, "dht_enabled", False)),
            "dhtK": int(getattr(config.network, "dht_k", 20)),
            "randomizeUdpPort": bool(getattr(config.network, "randomize_udp_port", True)),
            "upnpEnabled": bool(getattr(config.network, "upnp_enabled", False)),
            "natPmpEnabled": bool(getattr(config.network, "nat_pmp_enabled", False)),
            "preferredTunnelPorts": list(getattr(config.network, "preferred_tunnel_ports", [443, 80])),
            "outgoingOnly": bool(getattr(config.network, "outgoing_only", False)),
        }

    def _sync_peer_connector_settings() -> None:
        connectors = [candidate for candidate in (peer_connector, *relay_transports.values()) if candidate is not None]
        if not connectors:
            return
        peers = _list_active_peers()
        stats = chunk_store.stats()
        for connector in connectors:
            for name, value in {
                "client_type": config.node.client_type,
                "shared_storage_bytes": config.storage.limit_bytes,
                "free_storage_bytes": stats.free_limit_bytes,
                "accepts_peer_storage": _accepts_peer_storage(peers),
                "web_port": config.web.port,
                "relay_urls": _relay_url_list(),
                "relay_discovery_callback": _learn_relay_urls,
            }.items():
                if hasattr(connector, name):
                    setattr(connector, name, value)

    def _dispatch_relay_request(envelope: dict[str, Any]) -> RelayHttpResponse:
        method = str(envelope.get("method", "GET")).upper()
        path = str(envelope.get("path", ""))
        if method not in {"GET", "POST"} or not path.startswith("/api/p2p/"):
            return RelayHttpResponse(
                status_code=403,
                headers={"Content-Type": "application/json"},
                body=b'{"ok":false,"message":"Relay darf nur P2P-API-Endpunkte aufrufen"}',
            )
        try:
            body = base64.b64decode(str(envelope.get("body_base64", "")))
        except Exception:
            return RelayHttpResponse(
                status_code=400,
                headers={"Content-Type": "application/json"},
                body=b'{"ok":false,"message":"Relay-Nutzdaten sind ungueltig"}',
            )
        raw_headers = envelope.get("headers", {})
        allowed_headers: dict[str, str] = {}
        if isinstance(raw_headers, dict):
            for key, value in raw_headers.items():
                key_text = str(key)
                lower = key_text.lower()
                if lower in {"content-type", "accept"} or lower.startswith("x-dcloud-"):
                    allowed_headers[key_text] = str(value)
        with app.test_client() as relay_client_for_app:
            response = relay_client_for_app.open(path, method=method, headers=allowed_headers, data=body)
        return RelayHttpResponse(
            status_code=int(response.status_code),
            headers={"Content-Type": response.content_type or "application/octet-stream"},
            body=response.get_data(),
        )

    def _stop_relay_transport() -> None:
        with relay_lock:
            for transport in list(relay_transports.values()):
                transport.stop()
            relay_transports.clear()
            relay_clients.clear()
            p2p_client.clear_relay_clients()
            app.config["DCLOUD_RELAY_TRANSPORT"] = None
            app.config["DCLOUD_RELAY_TRANSPORTS"] = {}

    def _learn_relay_urls(urls: list[str]) -> None:
        if not config.network.relay_urls:
            # User has explicitly disabled PHP relay usage in settings.
            return
        new_urls = [url for url in normalize_relay_urls(urls, include_default=False) if url not in config.network.relay_urls]
        if not new_urls:
            return
        try:
            persist_relay_urls(config, [*config.network.relay_urls, *new_urls])
        except Exception:
            # Keep the discovered relays at least for the current runtime if the
            # config file cannot be updated.
            config.network.relay_urls = normalize_relay_urls([config.network.relay_urls, new_urls], include_default=True)
            config.network.relay_url = config.network.relay_urls[0] if config.network.relay_urls else DEFAULT_PUBLIC_RELAY_URL
        _configure_relay_transport()
        _sync_peer_connector_settings()

    def _configure_relay_transport() -> None:
        desired_urls = _relay_url_list()
        with relay_lock:
            for url in list(relay_transports):
                client = relay_clients.get(url)
                if url not in desired_urls or client is None:
                    relay_transports[url].stop()
                    relay_transports.pop(url, None)
                    relay_clients.pop(url, None)
            for desired_url in desired_urls:
                if desired_url in relay_transports:
                    continue
                relay_client = HttpRelayClient(
                    relay_url=desired_url,
                    identity=identity,
                    secret="",
                    timeout=5.0,
                    request_timeout=getattr(config.network, "relay_request_timeout_seconds", 90),
                )
                relay_transport = HttpRelayTransport(
                    relay_client=relay_client,
                    identity=identity,
                    node_name=config.node.name,
                    peer_provider=peer_provider,
                    dispatcher=_dispatch_relay_request,
                    protocol_magic=config.security.protocol_magic,
                    udp_port=active_udp_port,
                    web_port=config.web.port,
                    client_type=config.node.client_type,
                    shared_storage_bytes=config.storage.limit_bytes,
                    free_storage_bytes=chunk_store.stats().free_limit_bytes,
                    accepts_peer_storage=_accepts_peer_storage(_list_active_peers()),
                    poll_interval_seconds=getattr(config.network, "relay_poll_interval_seconds", 1),
                    peer_timeout_seconds=getattr(config.network, "peer_timeout_seconds", 35),
                    relay_urls=desired_urls,
                    relay_discovery_callback=_learn_relay_urls,
                    metadata_provider=lambda: {
                        "shared_storage_bytes": config.storage.limit_bytes,
                        "free_storage_bytes": chunk_store.stats().free_limit_bytes,
                        "accepts_peer_storage": _accepts_peer_storage(_list_active_peers()),
                    },
                )
                relay_clients[desired_url] = relay_client
                relay_transports[desired_url] = relay_transport
                relay_transport.start()
            p2p_client.set_relay_clients(relay_clients)
            app.config["DCLOUD_RELAY_TRANSPORTS"] = dict(relay_transports)
            app.config["DCLOUD_RELAY_TRANSPORT"] = next(iter(relay_transports.values()), None)
        _sync_peer_connector_settings()

    def _deliver_pending_share_revocations(peers: list[Any] | None = None) -> tuple[int, int]:
        """Best-effort delivery of queued share removals to active peers."""
        active_peers = peers if peers is not None else _list_active_peers()
        delivered = 0
        failed = 0
        for revocation in manifest_store.list_pending_share_revocations(identity.node_id):
            try:
                verify_manifest_revocation(revocation)
            except StorageError:
                continue
            target_ids = {str(node_id) for node_id in revocation.get("target_node_ids", []) if str(node_id)}
            delivered_ids = {str(node_id) for node_id in revocation.get("delivered_node_ids", []) if str(node_id)}
            for peer in active_peers:
                if peer.node_id in delivered_ids:
                    continue
                if "*" not in target_ids and peer.node_id not in target_ids:
                    continue
                result = p2p_client.post_manifest_revocation(peer, revocation)
                if result.ok:
                    manifest_store.mark_share_revocation_delivered(
                        str(revocation["manifest_id"]),
                        identity.node_id,
                        peer.node_id,
                    )
                    delivered += 1
                else:
                    failed += 1
        return delivered, failed

    def _manifest_delete_target_node_ids(manifest: FileManifest) -> list[str]:
        """Return every peer that may hold a manifest copy or stored chunks."""
        targets: list[str] = []
        for chunk in manifest.chunks:
            targets.extend(str(node_id) for node_id in chunk.get("locations", []) if str(node_id))
        if manifest.placement:
            targets.extend(str(node_id) for node_id in manifest.placement.get("targets", []) if str(node_id))
        access = manifest.access or {}
        if access.get("visibility") in {"shared", "public"}:
            shared_with = [str(node_id) for node_id in access.get("shared_with", []) if str(node_id)]
            targets.extend(shared_with or ["*"])
        cleaned: list[str] = []
        for node_id in targets:
            if node_id == identity.node_id:
                continue
            if node_id not in cleaned:
                cleaned.append(node_id)
        return cleaned

    def _deliver_pending_file_deletions(peers: list[Any] | None = None) -> tuple[int, int]:
        """Best-effort delivery of queued full-file deletions to active peers."""
        active_peers = peers if peers is not None else _list_active_peers()
        delivered = 0
        failed = 0
        for deletion in manifest_store.list_pending_file_deletions(identity.node_id):
            try:
                verify_manifest_deletion(deletion)
            except StorageError:
                continue
            target_ids = {str(node_id) for node_id in deletion.get("target_node_ids", []) if str(node_id)}
            delivered_ids = {str(node_id) for node_id in deletion.get("delivered_node_ids", []) if str(node_id)}
            for peer in active_peers:
                if peer.node_id in delivered_ids:
                    continue
                if "*" not in target_ids and peer.node_id not in target_ids:
                    continue
                result = p2p_client.post_manifest_deletion(peer, deletion)
                if result.ok:
                    manifest_store.mark_file_deletion_delivered(
                        str(deletion["manifest_id"]),
                        identity.node_id,
                        peer.node_id,
                    )
                    delivered += 1
                else:
                    failed += 1
        return delivered, failed

    def _delete_owned_manifest_with_peer_cleanup(manifest: FileManifest) -> dict[str, int]:
        """Delete an owned manifest locally and ask peers to remove copies/chunks."""
        if manifest.owner_node_id != identity.node_id:
            raise StorageError("Only the owner can delete this manifest")
        target_node_ids = _manifest_delete_target_node_ids(manifest)
        delivered = 0
        failed = 0
        if target_node_ids:
            deletion = build_manifest_deletion(manifest, identity)
            manifest_store.add_file_deletion(deletion, target_node_ids)
            delivered, failed = _deliver_pending_file_deletions()
        manifest_store.delete(manifest.manifest_id)
        _sync_peer_connector_settings()
        return {
            "target_count": len(target_node_ids),
            "delivered": delivered,
            "failed": failed,
            "queued": max(len(target_node_ids) - delivered, 0),
        }

    def _remove_smb_virtual_file(manifest: FileManifest) -> None:
        """Remove mirrored SMB file for a manifest if the SMB root is configured."""
        smb_root_raw = app.config.get("DCLOUD_SMB_ROOT")
        if not smb_root_raw:
            return
        smb_root = Path(str(smb_root_raw))
        target = smb_root / Path(manifest.folder_path or DEFAULT_FOLDER) / manifest.file_name
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass

    def manifest_payload(manifest: FileManifest) -> dict[str, Any]:
        locations = list(dict.fromkeys(
            str(location)
            for chunk in manifest.chunks
            for location in chunk.get("locations", [])
            if str(location)
        ))
        return {
            "manifest_id": manifest.manifest_id,
            "file_name": manifest.file_name,
            "file_size": manifest.file_size,
            "chunk_count": len(manifest.chunks),
            "folder_path": manifest.folder_path,
            "owner_node_id": manifest.owner_node_id,
            "access": manifest.access or {"visibility": "private", "shared_with": []},
            "placement": manifest.placement or {},
            "storage_locations": locations,
            "remote_storage_count": len([node_id for node_id in locations if node_id != identity.node_id]),
            "download_url": url_for("download", manifest_id=manifest.manifest_id),
            "delete_url": url_for("delete_file", manifest_id=manifest.manifest_id),
            "share_url": url_for("share_file", manifest_id=manifest.manifest_id),
            "offload_url": url_for("offload_file_chunks", manifest_id=manifest.manifest_id),
        }

    def folder_tree_json(folder_tree: list[dict[str, object]]) -> list[dict[str, object]]:
        payload: list[dict[str, object]] = []
        for folder in folder_tree:
            files = []
            for manifest in folder["files"]:
                assert isinstance(manifest, FileManifest)
                files.append(manifest_payload(manifest))
            payload.append({"name": folder["name"], "files": files})
        return payload

    def state_payload() -> dict[str, Any]:
        _sync_peer_connector_settings()
        stats = chunk_store.stats()
        peers = _list_active_peers()
        _repair_under_replicated_manifests(peers)
        _deliver_pending_share_revocations(peers)
        _deliver_pending_file_deletions(peers)
        manifests = manifest_store.list_visible_for_node(identity.node_id)
        folders = manifest_store.list_folders_for_node(identity.node_id)
        tree = build_folder_tree(manifests, folders)
        return {
            "stateVersion": time.time_ns(),
            "nodeId": identity.node_id,
            "stats": stats_payload(stats),
            "settings": settings_payload(stats, peers),
            "network": network_payload(),
            "networkCapacity": _network_storage_capacity(stats, peers),
            "peers": [peer.to_dict() for peer in peers],
            "fileCount": len(manifests),
            "folders": folders,
            "folderTree": folder_tree_json(tree),
            "gitRevision": current_git_revision(),
        }

    @app.get("/")
    def dashboard() -> str:
        stats = chunk_store.stats()
        manifests = manifest_store.list_visible_for_node(identity.node_id)
        folders = manifest_store.list_folders_for_node(identity.node_id)
        tree = build_folder_tree(manifests, folders)
        return render_template(
            "dashboard.html",
            config=config,
            identity=identity,
            stats=stats,
            stats_json=stats_payload(stats),
            peers=_list_active_peers(),
            peers_json=[peer.to_dict() for peer in _list_active_peers()],
            settings_json=settings_payload(stats),
            network_json=network_payload(),
            manifests=manifests,
            folder_tree=tree,
            folder_tree_json=folder_tree_json(tree),
            folders=folders,
            default_folder=DEFAULT_FOLDER,
            git_revision=current_git_revision(),
        )

    @app.get("/files")
    def files() -> str:
        manifests = manifest_store.list_visible_for_node(identity.node_id)
        folders = manifest_store.list_folders_for_node(identity.node_id)
        return render_template(
            "files.html",
            manifests=manifests,
            folder_tree=build_folder_tree(manifests, folders),
            folders=folders,
            identity=identity,
            default_folder=DEFAULT_FOLDER,
        )

    @app.get("/api/state")
    def api_state() -> Response:
        response = jsonify(state_payload())
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    @app.get("/api/logs")
    def api_logs() -> Response:
        manifest_log_path = manifest_store.audit_log_path
        manifest_log = _tail_text_file(manifest_log_path)
        if not manifest_log:
            manifest_log = "Keine Audit-Logs gefunden."
        return jsonify(
            {
                "manifestAuditPath": str(manifest_log_path),
                "manifestAuditLog": manifest_log,
                "updatedAt": datetime.now(timezone.utc).isoformat(),
            }
        )

    @app.get("/api/uploads/<upload_id>")
    def api_upload_progress(upload_id: str) -> Response:
        return jsonify(upload_progress.get(_safe_upload_id(upload_id)))

    @app.get("/api/uploads")
    def api_upload_progress_list() -> Response:
        include_finished = request.args.get("include_finished", "1").strip() != "0"
        limit_raw = request.args.get("limit", "12").strip()
        try:
            limit = max(1, min(50, int(limit_raw or "12")))
        except ValueError:
            limit = 12
        return jsonify({"uploads": upload_progress.list_recent(include_finished=include_finished, limit=limit)})

    @app.get("/api/chat")
    def api_chat_list() -> Response:
        peer_id = str(request.args.get("peer_id", "")).strip()
        if not peer_id:
            return jsonify({"ok": False, "message": "peer_id fehlt"}), 400
        return jsonify({"ok": True, "peerId": peer_id, "messages": list(chat_messages.get(peer_id, []))})

    @app.post("/api/chat/send")
    def api_chat_send() -> Response:
        payload = request.get_json(silent=True) or {}
        peer_id = str(payload.get("peer_id", "")).strip()
        text = str(payload.get("text", "")).strip()
        if not peer_id or not text:
            return jsonify({"ok": False, "message": "peer_id und text sind erforderlich"}), 400
        peers = _list_active_peers()
        peer = next((item for item in peers if item.node_id == peer_id), None)
        if peer is None:
            return jsonify({"ok": False, "message": "Peer ist nicht aktiv erreichbar"}), 404
        now = datetime.now(timezone.utc).isoformat()
        outgoing = {"from_node_id": identity.node_id, "to_node_id": peer_id, "text": text, "created_at": now}
        transfer = p2p_client._post_json_to_peer(  # noqa: SLF001
            peer,
            path="/api/p2p/chat",
            payload=outgoing,
            success_message="chat delivered",
            log_message="Chat message to peer %s failed",
        )
        if not transfer.ok:
            return jsonify({"ok": False, "message": transfer.message or "Chat konnte nicht zugestellt werden"}), 502
        local_event = {**outgoing, "direction": "out"}
        chat_messages[peer_id].append(local_event)
        return jsonify({"ok": True, "message": local_event})

    def _requested_storage_peers() -> list[Any]:
        available_peers = _eligible_storage_peers()
        requested_peer_ids = [str(peer_id).strip() for peer_id in request.form.getlist("storage_peer_node_ids") if str(peer_id).strip()]
        if not requested_peer_ids:
            return available_peers
        requested_set = set(requested_peer_ids)
        selected = [peer for peer in available_peers if peer.node_id in requested_set]
        return selected or available_peers

    def _store_uploaded_temp_file(temp_path: Path, safe_name: str, folder_path: str, upload_id: str, storage_peers: list[Any] | None = None) -> tuple[bool, dict[str, Any], int]:
        file_size = temp_path.stat().st_size
        _sync_peer_connector_settings()
        storage_peers = storage_peers if storage_peers is not None else _requested_storage_peers()
        upload_progress.update(
            upload_id,
            phase="select_targets",
            status="Speicherziele werden ausgewählt…",
            percent=40,
            server_percent=4,
            total_bytes=file_size,
            target_count=len(storage_peers) + 1,
            details={"peerTargets": [peer.to_dict().get("display_name") or peer.node_id[:12] for peer in storage_peers]},
        )
        uses_relay_storage = any(getattr(peer, "host", "") == RELAY_HOST for peer in storage_peers)
        relay_safe_chunk_size = int(getattr(config.network, "relay_chunk_size_bytes", 512 * 1024))
        effective_chunk_size = min(chunk_store.chunk_size, relay_safe_chunk_size) if uses_relay_storage else chunk_store.chunk_size
        upload_result = distribute_file_chunks(source_path=temp_path, chunk_store=chunk_store, local_node_id=identity.node_id, peers=storage_peers, p2p_client=p2p_client, progress_callback=_upload_server_progress(upload_id), chunk_size_bytes=effective_chunk_size)
        placement = {"strategy": "distributed_round_robin_chunks", "target_count": len(upload_result.targets), "targets": upload_result.targets, "transfer_status": upload_result.transfer_status, "remote_successes": upload_result.remote_successes, "remote_failures": upload_result.remote_failures, "local_chunks": upload_result.local_chunks, "compressed_chunks": upload_result.compressed_chunks, "desired_replicas": upload_result.desired_replicas, "replicated_chunks": upload_result.replicated_chunks, "under_replicated_chunks": upload_result.under_replicated_chunks, "raw_bytes": upload_result.raw_bytes, "stored_bytes": upload_result.stored_bytes}
        manifest = manifest_store.create_from_chunk_entries(file_name=safe_name, file_size=file_size, chunk_entries=upload_result.chunks, identity=identity, folder_path=folder_path, placement=placement)
        return True, {"manifest": manifest, "upload_result": upload_result}, file_size

    @app.post("/upload/smb")
    def upload_from_smb() -> Response:
        upload_id = _safe_upload_id(request.form.get("upload_id"))
        if SMBConnection is None:
            message = "SMB-Unterstuetzung ist nicht installiert (Python-Modul 'smb' fehlt)."
            upload_progress.fail(upload_id, message)
            return jsonify({"ok": False, "message": message, "uploadId": upload_id, "uploadProgress": upload_progress.get(upload_id)}), 503
        folder_path = sanitize_folder_path(request.form.get("folder", DEFAULT_FOLDER))
        host = (request.form.get("smb_host") or "").strip()
        share = (request.form.get("smb_share") or "").strip()
        remote_path = (request.form.get("smb_path") or "").strip().replace("\\", "/")
        username = request.form.get("smb_username") or ""
        password = request.form.get("smb_password") or ""
        domain = request.form.get("smb_domain") or ""
        if not host or not share or not remote_path:
            return jsonify({"ok": False, "message": "SMB Host, Freigabe und Dateipfad sind erforderlich."}), 400
        safe_name = secure_filename(Path(remote_path).name) or "smb_upload.bin"
        upload_progress.start(upload_id, file_name=safe_name, folder_path=folder_path)
        storage_peers = _requested_storage_peers()
        with tempfile.NamedTemporaryFile(prefix="upload-smb-", suffix=".tmp", dir=chunk_store.tmp_dir, delete=False) as tmp:
            temp_path = Path(tmp.name)
        try:
            upload_progress.update(upload_id, phase="smb_connect", status="SMB-Verbindung wird aufgebaut…", percent=8, server_percent=0)
            client_name = socket.gethostname()[:15] or "dcloud"
            conn = SMBConnection(username, password, client_name, host, domain=domain, use_ntlm_v2=True, is_direct_tcp=True)
            if not conn.connect(host, 445, timeout=20):
                raise StorageError("SMB-Verbindung konnte nicht aufgebaut werden")
            with temp_path.open("wb") as out:
                conn.retrieveFile(share, remote_path, out)
            conn.close()
            upload_progress.update(upload_id, phase="smb_downloaded", status="Datei vom SMB-Share geladen, verarbeite Upload…", percent=35, server_percent=2)
            ok, payload, _ = _store_uploaded_temp_file(temp_path, safe_name, folder_path, upload_id, storage_peers=storage_peers)
            manifest = payload["manifest"]
            return jsonify({"ok": ok, "message": f"SMB-Datei importiert: {safe_name}", "manifest": manifest_payload(manifest), "state": state_payload(), "uploadId": upload_id, "uploadProgress": upload_progress.get(upload_id)})
        except Exception as exc:
            upload_progress.finish(upload_id, ok=False, message=str(exc))
            return jsonify({"ok": False, "message": f"SMB-Import fehlgeschlagen: {exc}", "uploadId": upload_id, "uploadProgress": upload_progress.get(upload_id)}), 400
        finally:
            temp_path.unlink(missing_ok=True)

    @app.post("/upload")
    def upload() -> Response | str:
        header_upload_id = request.headers.get("X-DCloud-Upload-Id")
        upload_id = _safe_upload_id(header_upload_id or request.form.get("upload_id"))
        if header_upload_id:
            upload_progress.update(
                upload_id,
                phase="receiving",
                status="Browser überträgt die Datei an den lokalen Client…",
                percent=5,
                server_percent=0,
            )
        redirect_target = _safe_next(request.form.get("next"), url_for("dashboard"))
        uploaded = request.files.get("file")
        if uploaded is None or uploaded.filename == "":
            message = "Keine Datei ausgewählt"
            upload_progress.finish(upload_id, ok=False, message=message)
            if _is_ajax_request():
                return jsonify({"ok": False, "message": message, "state": state_payload(), "uploadId": upload_id, "uploadProgress": upload_progress.get(upload_id)}), 400
            flash(message, "error")
            return redirect(redirect_target)
        safe_name = secure_filename(uploaded.filename) or "upload.bin"
        folder_path = sanitize_folder_path(request.form.get("folder", DEFAULT_FOLDER))
        upload_progress.start(upload_id, file_name=safe_name, folder_path=folder_path)
        with tempfile.NamedTemporaryFile(prefix="upload-", suffix=".tmp", dir=chunk_store.tmp_dir, delete=False) as tmp:
            temp_path = Path(tmp.name)
        try:
            upload_progress.update(
                upload_id,
                phase="saving_temp",
                status="Datei wurde übertragen; temporäre Kopie wird geschrieben…",
                percent=38,
                server_percent=2,
            )
            uploaded.save(temp_path)
            file_size = temp_path.stat().st_size
            _sync_peer_connector_settings()
            storage_peers = _requested_storage_peers()
            upload_progress.update(
                upload_id,
                phase="select_targets",
                status="Speicherziele werden ausgewählt…",
                percent=40,
                server_percent=4,
                total_bytes=file_size,
                target_count=len(storage_peers) + 1,
                details={
                    "peerTargets": [peer.to_dict().get("display_name") or peer.node_id[:12] for peer in storage_peers],
                },
            )
            uses_relay_storage = any(getattr(peer, "host", "") == RELAY_HOST for peer in storage_peers)
            relay_safe_chunk_size = int(getattr(config.network, "relay_chunk_size_bytes", 512 * 1024))
            effective_chunk_size = min(chunk_store.chunk_size, relay_safe_chunk_size) if uses_relay_storage else chunk_store.chunk_size
            if uses_relay_storage and effective_chunk_size < chunk_store.chunk_size:
                upload_progress.update(
                    upload_id,
                    phase="relay_chunk_size",
                    status=(
                        "PHP-Relay erkannt; Chunks werden kleiner geschnitten, "
                        "damit Webserver-POST-Limits nicht greifen…"
                    ),
                    percent=42,
                    server_percent=6,
                    details={
                        "relayChunkSize": effective_chunk_size,
                        "configuredChunkSize": chunk_store.chunk_size,
                    },
                )
            upload_result = distribute_file_chunks(
                source_path=temp_path,
                chunk_store=chunk_store,
                local_node_id=identity.node_id,
                peers=storage_peers,
                p2p_client=p2p_client,
                progress_callback=_upload_server_progress(upload_id),
                chunk_size_bytes=effective_chunk_size,
            )
            placement = {
                "strategy": "distributed_round_robin_chunks",
                "target_count": len(upload_result.targets),
                "targets": upload_result.targets,
                "transfer_status": upload_result.transfer_status,
                "remote_successes": upload_result.remote_successes,
                "remote_failures": upload_result.remote_failures,
                "local_chunks": upload_result.local_chunks,
                "compressed_chunks": upload_result.compressed_chunks,
                "desired_replicas": upload_result.desired_replicas,
                "replicated_chunks": upload_result.replicated_chunks,
                "under_replicated_chunks": upload_result.under_replicated_chunks,
                "raw_bytes": upload_result.raw_bytes,
                "stored_bytes": upload_result.stored_bytes,
            }
            upload_progress.update(
                upload_id,
                phase="manifest",
                status="Manifest wird geschrieben und Dateiliste aktualisiert…",
                percent=99,
                server_percent=98,
                raw_bytes_processed=upload_result.raw_bytes,
                stored_bytes=upload_result.stored_bytes,
                compressed_chunks=upload_result.compressed_chunks,
                local_chunks=upload_result.local_chunks,
                remote_successes=upload_result.remote_successes,
                remote_failures=upload_result.remote_failures,
                desired_replicas=upload_result.desired_replicas,
                target_count=len(upload_result.targets),
            )
            manifest = manifest_store.create_from_chunk_entries(
                file_name=safe_name,
                file_size=file_size,
                chunk_entries=upload_result.chunks,
                identity=identity,
                folder_path=folder_path,
                placement=placement,
            )
            if upload_result.remote_successes:
                replica_note = f", {upload_result.replicated_chunks} redundant" if upload_result.replicated_chunks else ""
                message = (
                    f"Datei verteilt gespeichert: {safe_name} in {folder_path} "
                    f"({upload_result.remote_successes} Peer-Schreibvorgang/-vorgänge, "
                    f"{upload_result.local_chunks} lokal{replica_note})"
                )
            elif upload_result.remote_failures:
                message = f"Datei lokal gespeichert: {safe_name}; Peer-Ablage war nicht erreichbar"
            else:
                message = f"Datei lokal gespeichert: {safe_name} in {folder_path} ({manifest.manifest_id[:12]})"
            upload_progress.finish(
                upload_id,
                ok=True,
                message=message,
                details={
                    "manifestId": manifest.manifest_id,
                    "transferStatus": upload_result.transfer_status,
                    "rawBytes": upload_result.raw_bytes,
                    "storedBytes": upload_result.stored_bytes,
                    "replicatedChunks": upload_result.replicated_chunks,
                    "underReplicatedChunks": upload_result.under_replicated_chunks,
                },
            )
            if _is_ajax_request():
                return jsonify({
                    "ok": True,
                    "message": message,
                    "manifest": manifest_payload(manifest),
                    "state": state_payload(),
                    "uploadId": upload_id,
                    "uploadProgress": upload_progress.get(upload_id),
                })
            flash(message, "success")
        except StorageError as exc:
            message = str(exc)
            upload_progress.finish(upload_id, ok=False, message=message)
            if _is_ajax_request():
                return jsonify({"ok": False, "message": message, "state": state_payload(), "uploadId": upload_id, "uploadProgress": upload_progress.get(upload_id)}), 400
            flash(message, "error")
        finally:
            temp_path.unlink(missing_ok=True)
        return redirect(redirect_target)

    @app.post("/folders")
    def create_folder() -> Response | str:
        folder_path = request.form.get("folder", "").strip()
        redirect_target = _safe_next(request.form.get("next"), url_for("dashboard"))
        if not folder_path:
            message = "Ordnername darf nicht leer sein"
            if _is_ajax_request():
                return jsonify({"ok": False, "message": message, "state": state_payload()}), 400
            flash(message, "error")
            return redirect(redirect_target)
        created = manifest_store.create_folder(folder_path, identity.node_id)
        message = f"Ordner erstellt: {created}"
        if _is_ajax_request():
            return jsonify({"ok": True, "message": message, "folder": created, "state": state_payload()})
        flash(message, "success")
        return redirect(redirect_target)

    @app.post("/folders/delete")
    def delete_folder() -> Response | str:
        folder_path = sanitize_folder_path(request.form.get("folder", ""))
        redirect_target = _safe_next(request.form.get("next"), url_for("dashboard"))
        try:
            if not folder_path:
                raise StorageError("Ordnername darf nicht leer sein")
            if folder_path == DEFAULT_FOLDER:
                raise StorageError("Der Standardordner kann nicht gelöscht werden")
            visible_folders = manifest_store.list_folders_for_node(identity.node_id)
            exists = folder_path in visible_folders or any(folder.startswith(f"{folder_path}/") for folder in visible_folders)
            if not exists:
                raise StorageError(f"Ordner nicht gefunden: {folder_path}")
            def is_in_folder(candidate: str) -> bool:
                candidate = sanitize_folder_path(candidate)
                return candidate == folder_path or candidate.startswith(f"{folder_path}/")

            owned_manifests = [
                manifest
                for manifest in manifest_store.list_manifests()
                if manifest.owner_node_id == identity.node_id and is_in_folder(manifest.folder_path)
            ]
            peer_cleanup = {"target_count": 0, "delivered": 0, "failed": 0, "queued": 0}
            for manifest in owned_manifests:
                cleanup = _delete_owned_manifest_with_peer_cleanup(manifest)
                _remove_smb_virtual_file(manifest)
                for key in peer_cleanup:
                    peer_cleanup[key] += int(cleanup.get(key, 0))

            result = manifest_store.delete_folder(folder_path, identity.node_id, delete_files=False)
            result["deleted_files"] = len(owned_manifests)
            result["peer_cleanup"] = peer_cleanup
            if int(result["deleted_files"]) == 0 and int(result["deleted_folders"]) == 0:
                raise StorageError("Nur eigene Ordner und Dateien können gelöscht werden")

            details: list[str] = []
            if int(result["deleted_files"]):
                details.append(f"{result['deleted_files']} Datei(en)")
            if int(result["deleted_folders"]):
                details.append(f"{result['deleted_folders']} Ordner")
            if peer_cleanup["delivered"]:
                details.append(f"Peer-Bereinigung an {peer_cleanup['delivered']} Peer(s)")
            elif peer_cleanup["target_count"]:
                details.append("Peer-Bereinigung vorgemerkt")
            suffix = f" ({', '.join(details)} entfernt)" if details else ""
            message = f"Ordner gelöscht: {result['folder']}{suffix}"
            if _is_ajax_request():
                return jsonify({"ok": True, "message": message, "folder": result["folder"], "deleted": result, "state": state_payload()})
            flash(message, "success")
        except StorageError as exc:
            message = str(exc)
            if _is_ajax_request():
                return jsonify({"ok": False, "message": message, "state": state_payload()}), 400
            flash(message, "error")
        return redirect(redirect_target)

    def _share_target_peers(target_value: str) -> tuple[list[Any], list[str]]:
        peers = _list_active_peers()
        target_value = (target_value or "*").strip()
        if target_value in {"*", "all", "alle"}:
            return peers, ["*"]
        selected = [peer for peer in peers if peer.node_id == target_value]
        if not selected:
            raise StorageError("Ausgewählter Peer ist nicht mehr aktiv")
        return selected, [target_value]

    def _single_target_peer(target_value: str) -> Any:
        target_value = (target_value or "").strip()
        if not target_value:
            raise StorageError("Bitte ein Ziel-Peer auswählen")
        peers = _list_active_peers()
        for peer in peers:
            if peer.node_id == target_value:
                return peer
        raise StorageError("Ausgewählter Ziel-Peer ist nicht mehr aktiv")

    @app.post("/files/<manifest_id>/offload")
    def offload_file_chunks(manifest_id: str) -> Response | str:
        redirect_target = _safe_next(request.form.get("next"), url_for("files"))
        try:
            manifest = manifest_store.load(manifest_id)
            if manifest.owner_node_id != identity.node_id:
                raise StorageError("Nur der Eigentümer kann Chunk-Daten auslagern")
            target_peer_id = (request.form.get("target_peer_node_id") or "").strip()
            add_only = request.form.get("add_only", "0") in {"1", "true", "on", "yes"}
            if target_peer_id:
                peers = [_single_target_peer(target_peer_id)]
            else:
                peers = _eligible_storage_peers()
            if not peers:
                raise StorageError("Keine aktiven Speicher-Peers verfügbar")

            updated_chunks: list[dict[str, Any]] = []
            remote_successes = 0
            local_removed = 0
            remote_failures = 0
            removal_candidates: list[str] = []

            for chunk in manifest.chunks:
                entry = dict(chunk)
                digest = str(entry.get("hash") or "")
                if not digest:
                    updated_chunks.append(entry)
                    continue
                try:
                    stored_data = chunk_store.read_stored_chunk(digest)
                except StorageError:
                    # Chunk liegt bereits nur extern vor.
                    updated_chunks.append(entry)
                    continue

                locations = [str(value) for value in entry.get("locations", []) if str(value) and str(value) != identity.node_id]
                written = False
                for peer in peers:
                    if peer.node_id in locations:
                        written = True
                        continue
                    transfer = p2p_client.put_chunk(
                        peer,
                        digest=digest,
                        stored_data=stored_data,
                        original_size=int(entry.get("size") or 0),
                        stored_size=int(entry.get("stored_size") or len(stored_data)),
                        index=int(entry.get("index") or 0),
                        compression=str(entry.get("compression") or "") or None,
                    )
                    if transfer.ok:
                        locations.append(peer.node_id)
                        remote_successes += 1
                        written = True
                        break
                    remote_failures += 1

                if written:
                    if add_only:
                        entry["locations"] = list(dict.fromkeys([*locations, identity.node_id])) or [identity.node_id]
                    else:
                        removal_candidates.append(digest)
                        local_removed += 1
                        entry["locations"] = list(dict.fromkeys(locations))
                else:
                    # Sicherheit: lokale Kopie bleibt erhalten, falls kein Peer erreichbar war.
                    entry["locations"] = list(dict.fromkeys([*locations, identity.node_id])) or [identity.node_id]
                updated_chunks.append(entry)

            new_targets = list(dict.fromkeys(location for chunk in updated_chunks for location in chunk.get("locations", [])))
            placement = dict(manifest.placement or {})
            placement.update({
                "strategy": "peer_additional_replica" if add_only else "peer_offload",
                "targets": new_targets,
                "target_count": len(new_targets),
                "transfer_status": "replicated_with_local_copy" if add_only else ("stored_on_peers" if local_removed else "local_only"),
                "offloaded_local_chunks": local_removed,
                "offload_remote_successes": remote_successes,
                "offload_remote_failures": remote_failures,
            })
            updated_manifest = manifest_store.update_placement(
                manifest.manifest_id,
                identity,
                chunks=updated_chunks,
                placement=placement,
            )
            # Chunk-Dateien nur löschen, wenn sie in keinem verbleibenden Manifest mehr referenziert werden.
            # So verlieren deduplizierte Dateien ihre gemeinsamen Chunk-Daten nicht.
            if removal_candidates:
                local_removed = manifest_store.delete_chunks_if_unreferenced(removal_candidates)
                placement["offloaded_local_chunks"] = local_removed
                placement["transfer_status"] = "replicated_with_local_copy" if add_only else ("stored_on_peers" if local_removed else "local_only")
                updated_manifest = manifest_store.update_placement(
                    updated_manifest.manifest_id,
                    identity,
                    placement=placement,
                )

            if add_only and remote_successes:
                message = f"Zusätzlicher Knoten erstellt: {remote_successes} Chunk-Kopie(n) auf Ziel-Peer übertragen (lokale Sicherheitskopie bleibt erhalten)"
            elif add_only:
                message = "Keine zusätzliche Kopie erstellt; lokale Daten bleiben unverändert erhalten"
            elif local_removed:
                message = f"Auslagerung abgeschlossen: {local_removed} lokale Chunk(s) auf Peers verteilt"
            else:
                message = "Keine Chunks ausgelagert; lokale Daten bleiben erhalten"
            if _is_ajax_request():
                return jsonify({"ok": True, "message": message, "manifest": manifest_payload(updated_manifest), "state": state_payload()})
            flash(message, "success")
        except StorageError as exc:
            message = str(exc)
            if _is_ajax_request():
                return jsonify({"ok": False, "message": message, "state": state_payload()}), 400
            flash(message, "error")
        return redirect(redirect_target)

    @app.post("/files/<manifest_id>/share")
    def share_file(manifest_id: str) -> Response | str:
        redirect_target = _safe_next(request.form.get("next"), url_for("dashboard"))
        shared = request.form.get("shared") == "on"
        try:
            old_manifest = manifest_store.load(manifest_id)
            target_peers: list[Any] = []
            shared_with: list[str] = []
            if shared:
                target_peers, shared_with = _share_target_peers(request.form.get("peer_node_id", "*"))
            elif manifest_store.is_shared(old_manifest):
                previous_targets = [
                    str(item) for item in (old_manifest.access or {}).get("shared_with", []) if str(item)
                ]
                # Important: Never queue wildcard revocations.
                # Otherwise peers that were never shared with (e.g. after relay->LAN path
                # changes, reconnects, or newly discovered peers) can receive stale
                # revocation messages and delete freshly synced manifests.
                if not previous_targets:
                    previous_targets = [peer.node_id for peer in _list_active_peers() if peer.node_id != identity.node_id]
                revocation = build_manifest_revocation(old_manifest.manifest_id, identity)
                manifest_store.add_share_revocation(revocation, previous_targets)

            manifest = manifest_store.set_shared(manifest_id, shared, identity, shared_with=shared_with or None)
            if shared:
                manifest_store.clear_share_revocation(manifest.manifest_id, identity.node_id)

            delivered = 0
            failed = 0
            if shared:
                for peer in target_peers:
                    result = p2p_client.post_manifest(peer, manifest)
                    if result.ok:
                        delivered += 1
                    else:
                        failed += 1
            else:
                delivered, failed = _deliver_pending_share_revocations()

            if shared:
                if shared_with == ["*"]:
                    target_label = "alle aktiven Peers" if target_peers else "zukünftige Peers"
                else:
                    target_label = target_peers[0].to_dict().get("display_name") if target_peers else shared_with[0][:12]
                if failed and delivered:
                    message = f"Datei freigegeben für {target_label}; {failed} Peer(s) konnten das Manifest noch nicht empfangen"
                elif failed and not delivered:
                    message = f"Datei lokal freigegeben für {target_label}; Manifest-Transfer ist fehlgeschlagen"
                else:
                    message = f"Datei freigegeben für {target_label}: {manifest.file_name}"
            else:
                if delivered:
                    message = f"Datei privat gesetzt und Freigabe bei {delivered} Peer(s) entfernt: {manifest.file_name}"
                elif failed:
                    message = f"Datei privat gesetzt; entfernte Peer-Freigaben werden erneut bereinigt, sobald die Peers erreichbar sind: {manifest.file_name}"
                else:
                    message = f"Datei privat gesetzt: {manifest.file_name}"
            if _is_ajax_request():
                return jsonify({"ok": True, "message": message, "manifest": manifest_payload(manifest), "state": state_payload()})
            flash(message, "success")
        except StorageError as exc:
            message = str(exc)
            if _is_ajax_request():
                return jsonify({"ok": False, "message": message, "state": state_payload()}), 400
            flash(message, "error")
        return redirect(redirect_target)

    @app.post("/files/<manifest_id>/move")
    def move_file(manifest_id: str) -> Response | str:
        redirect_target = _safe_next(request.form.get("next"), url_for("dashboard"))
        target_folder = sanitize_folder_path(request.form.get("folder", DEFAULT_FOLDER))
        try:
            manifest = manifest_store.move_to_folder(manifest_id, target_folder, identity)
            message = f"Datei verschoben: {manifest.file_name} → {manifest.folder_path}"
            if _is_ajax_request():
                return jsonify({"ok": True, "message": message, "manifest": manifest_payload(manifest), "state": state_payload()})
            flash(message, "success")
        except StorageError as exc:
            message = str(exc)
            if _is_ajax_request():
                return jsonify({"ok": False, "message": message, "state": state_payload()}), 400
            flash(message, "error")
        return redirect(redirect_target)


    @app.post("/settings")
    def update_settings() -> Response | str:
        redirect_target = _safe_next(request.form.get("next"), url_for("dashboard"))
        try:
            update_runtime_settings(
                config,
                client_type="server",
                shared_storage_gb=request.form.get("shared_storage_gb", bytes_to_gib(config.storage.limit_bytes)),
                relay_server_url=request.form.get("relay_server_url"),
                relay_server_urls=request.form.get("relay_server_urls", request.form.get("relay_server_url", "\n".join(extra_relay_urls(config.network.relay_urls)))),
                relay_enabled=request.form.get("relay_enabled") == "on",
                smb_enabled=request.form.get("smb_enabled") == "on",
                smb_username=request.form.get("smb_username", config.smb.username),
                smb_password=request.form.get("smb_password", config.smb.password),
                dht_enabled=request.form.get("dht_enabled") == "on",
                dht_k=request.form.get("dht_k", getattr(config.network, "dht_k", 20)),
                randomize_udp_port=request.form.get("randomize_udp_port") == "on",
                upnp_enabled=request.form.get("upnp_enabled") == "on",
                nat_pmp_enabled=request.form.get("nat_pmp_enabled") == "on",
                preferred_tunnel_ports=request.form.get("preferred_tunnel_ports", ",".join(str(port) for port in getattr(config.network, "preferred_tunnel_ports", [443, 80]))),
                outgoing_only=request.form.get("outgoing_only") == "on",
            )
            chunk_store.limit_bytes = config.storage.limit_bytes
            _configure_relay_transport()
            _sync_peer_connector_settings()
            relay_note = ", PHP-Relay deaktiviert" if not config.network.relay_urls else f", {len(config.network.relay_urls)} PHP-Relay(s) aktiv"
            message = (
                f"Einstellungen gespeichert: {client_type_label(config.node.client_type)}, "
                f"{bytes_to_gib(config.storage.limit_bytes):g} GB freigegeben{relay_note}, "
                f"SMB {'aktiv' if config.smb.enabled else 'aus'} auf Port {config.smb.port}"
            )
            if _is_ajax_request():
                return jsonify({"ok": True, "message": message, "settings": settings_payload(), "state": state_payload()})
            flash(message, "success")
        except (TypeError, ValueError) as exc:
            message = str(exc)
            if _is_ajax_request():
                return jsonify({"ok": False, "message": message, "state": state_payload()}), 400
            flash(message, "error")
        return redirect(redirect_target)

    @app.post("/api/discovery/announce")
    def api_discovery_announce() -> Response:
        connectors = [candidate for candidate in (peer_connector, *relay_transports.values()) if candidate is not None and hasattr(candidate, "announce_once")]
        if not connectors:
            return jsonify({"ok": False, "message": "Peer-Discovery ist nicht verfügbar", "state": state_payload()}), 503
        successes = 0
        errors: list[str] = []
        for connector in connectors:
            try:
                connector.announce_once()
                successes += 1
            except Exception as exc:
                errors.append(str(exc))
        if successes:
            suffix = f"; {len(errors)} Relay/Connector(s) derzeit nicht erreichbar" if errors else ""
            return jsonify({"ok": True, "message": f"Netzwerksuche gestartet{suffix}", "state": state_payload()})
        message = "; ".join(errors) if errors else "Peer-Discovery ist nicht verfügbar"
        return jsonify({"ok": False, "message": f"Netzwerksuche fehlgeschlagen: {message}", "state": state_payload()}), 503

    @app.post("/api/storage/cleanup")
    def api_storage_cleanup() -> Response:
        cleanup = _cleanup_storage_garbage()
        total_removed = (
            cleanup["removed_unreferenced_chunks"]
            + cleanup["removed_stale_tmp_files"]
            + cleanup["removed_empty_chunk_dirs"]
        )
        if total_removed:
            message = (
                f"Datenmüll bereinigt: {cleanup['removed_unreferenced_chunks']} unreferenzierte Chunk(s), "
                f"{cleanup['removed_stale_tmp_files']} alte Temp-Datei(en), "
                f"{cleanup['removed_empty_chunk_dirs']} leere Chunk-Ordner."
            )
        else:
            message = "Keine bereinigbaren Daten gefunden."
        return jsonify({"ok": True, "message": message, "cleanup": cleanup, "state": state_payload()})


    @app.post("/peers")
    def add_peer() -> Response | str:
        peer_address = request.form.get("peer", "").strip()
        host, _, port_text = peer_address.rpartition(":")
        if not host or not port_text:
            flash("Peer bitte als host:port eintragen", "error")
            return redirect(url_for("dashboard"))
        try:
            port = int(port_text)
        except ValueError:
            flash("Peer-Port muss eine Zahl sein", "error")
            return redirect(url_for("dashboard"))
        if not 1 <= port <= 65535:
            flash("Peer-Port muss zwischen 1 und 65535 liegen", "error")
            return redirect(url_for("dashboard"))
        if peer_connector is None:
            flash("Peer-Verbindung ist nicht verfügbar", "error")
            return redirect(url_for("dashboard"))
        use_as_tree_parent = request.form.get("use_as_tree_parent") == "on"
        try:
            peer_connector.add_peer_address(host, port, use_as_tree_parent=use_as_tree_parent)
            mode = " als NAT-Parent" if use_as_tree_parent else ""
            flash(f"Peer-Austausch mit {host}:{port}{mode} gestartet", "success")
        except OSError as exc:
            flash(f"Peer konnte nicht kontaktiert werden: {exc}", "error")
        return redirect(url_for("dashboard"))

    def _ensure_manifest_chunks_available(manifest: FileManifest) -> None:
        peers_by_id = {peer.node_id: peer for peer in _list_active_peers()}
        all_peers = list(peers_by_id.values())
        for chunk in sorted(manifest.chunks, key=lambda item: int(item["index"])):
            digest = str(chunk["hash"])
            if chunk_store.chunk_path(digest).exists():
                continue
            tried: set[str] = set()
            restored = False
            candidate_ids = [str(node_id) for node_id in chunk.get("locations", []) if str(node_id)]
            candidate_ids.extend(peer.node_id for peer in all_peers)
            for node_id in candidate_ids:
                if node_id == identity.node_id or node_id in tried:
                    continue
                tried.add(node_id)
                peer = peers_by_id.get(node_id)
                if peer is None:
                    continue
                try:
                    stored_data = p2p_client.get_chunk(peer, digest=digest)
                    chunk_store.write_stored_chunk(
                        stored_data,
                        original_size=int(chunk["size"]),
                        index=int(chunk["index"]),
                        compression=str(chunk.get("compression")) if chunk.get("compression") else None,
                        digest=digest,
                    )
                    restored = True
                    break
                except StorageError:
                    continue
            if not restored:
                raise StorageError(f"Chunk {digest[:12]} ist aktuell auf keinem aktiven Peer erreichbar")

    @app.get("/download/<manifest_id>")
    def download(manifest_id: str) -> Response:
        manifest = manifest_store.load(manifest_id)
        if not manifest_store.may_access(manifest, identity.node_id):
            abort(404)
        try:
            _ensure_manifest_chunks_available(manifest)
            output = manifest_store.restore(manifest.manifest_id)
        except StorageError as exc:
            abort(503, str(exc))
        return send_file(output, as_attachment=True, download_name=manifest.file_name)

    @app.get("/api/p2p/chunks/<digest>")
    def api_p2p_get_chunk(digest: str) -> Response:
        blocked = _reject_if_outgoing_only()
        if blocked is not None:
            return blocked
        try:
            data = chunk_store.read_stored_chunk(digest)
        except StorageError:
            abort(404)
        return Response(data, mimetype="application/octet-stream")

    @app.post("/api/p2p/chunks/<digest>")
    def api_p2p_put_chunk(digest: str) -> Response:
        blocked = _reject_if_outgoing_only()
        if blocked is not None:
            return blocked
        compression = request.headers.get("X-DCloud-Chunk-Compression") or None
        try:
            original_size = int(request.headers.get("X-DCloud-Chunk-Original-Size", "0"))
            index = int(request.headers.get("X-DCloud-Chunk-Index", "0"))
            if original_size <= 0:
                raise ValueError
            info = chunk_store.write_stored_chunk(
                request.get_data(),
                original_size=original_size,
                index=index,
                compression=compression,
                digest=digest,
            )
            _sync_peer_connector_settings()
            return jsonify({"ok": True, "hash": info.hash, "stored_size": info.stored_size, "state": state_payload()})
        except (ValueError, StorageError) as exc:
            return jsonify({"ok": False, "message": str(exc), "state": state_payload()}), 400

    @app.post("/api/p2p/chunks/batch")
    def api_p2p_put_chunks_batch() -> Response:
        blocked = _reject_if_outgoing_only()
        if blocked is not None:
            return blocked
        try:
            payload = request.get_json(force=True)
            raw_chunks = payload.get("chunks", []) if isinstance(payload, dict) else []
            if not isinstance(raw_chunks, list) or not raw_chunks:
                raise StorageError("Batch payload must include at least one chunk")
            stored: list[str] = []
            for item in raw_chunks:
                if not isinstance(item, dict):
                    continue
                digest = str(item.get("digest", "")).strip()
                if not digest:
                    continue
                original_size = int(item.get("original_size", 0))
                index = int(item.get("index", 0))
                if original_size <= 0:
                    continue
                compression = str(item.get("compression")) if item.get("compression") else None
                encoded = str(item.get("stored_data_b64", ""))
                data = base64.b64decode(encoded.encode("ascii"), validate=True)
                chunk_store.write_stored_chunk(
                    data,
                    original_size=original_size,
                    index=index,
                    compression=compression,
                    digest=digest,
                )
                stored.append(digest)
            _sync_peer_connector_settings()
            return jsonify({"ok": True, "stored": stored, "stored_count": len(stored), "state": state_payload()})
        except (ValueError, StorageError, TypeError) as exc:
            return jsonify({"ok": False, "message": str(exc), "state": state_payload()}), 400

    @app.post("/api/p2p/manifests/revoke")
    def api_p2p_revoke_manifest() -> Response:
        blocked = _reject_if_outgoing_only()
        if blocked is not None:
            return blocked
        try:
            data = request.get_json(force=True)
            if not isinstance(data, dict):
                raise StorageError("Revocation payload must be a JSON object")
            owner_node_id = verify_manifest_revocation(data)
            manifest_id = str(data["manifest_id"])
            manifest_store.add_share_revocation(data, [])
            removed = False
            try:
                manifest = manifest_store.load(manifest_id)
            except StorageError:
                return jsonify({"ok": True, "manifest_id": manifest_id, "removed": False, "state": state_payload()})
            if manifest.owner_node_id != owner_node_id:
                raise StorageError("Revocation owner does not match manifest owner")
            if manifest.owner_node_id == identity.node_id:
                raise StorageError("Own manifests cannot be revoked through the peer API")
            manifest_store.delete(manifest_id, delete_unreferenced_chunks=False)
            removed = True
            return jsonify({"ok": True, "manifest_id": manifest_id, "removed": removed, "state": state_payload()})
        except (ValueError, TypeError, StorageError) as exc:
            return jsonify({"ok": False, "message": str(exc), "state": state_payload()}), 400

    @app.post("/api/p2p/files/delete")
    def api_p2p_delete_file() -> Response:
        blocked = _reject_if_outgoing_only()
        if blocked is not None:
            return blocked
        try:
            data = request.get_json(force=True)
            if not isinstance(data, dict):
                raise StorageError("File deletion payload must be a JSON object")
            deletion_manifest = verify_manifest_deletion(data)
            if deletion_manifest.owner_node_id == identity.node_id:
                raise StorageError("Own manifests cannot be deleted through the peer API")
            manifest_store.add_file_deletion(data, [])

            removed_manifest = False
            try:
                local_manifest = manifest_store.load(deletion_manifest.manifest_id)
            except StorageError:
                local_manifest = None
            if local_manifest is not None:
                if local_manifest.owner_node_id != deletion_manifest.owner_node_id:
                    raise StorageError("File deletion owner does not match local manifest owner")
                manifest_store.delete(local_manifest.manifest_id, delete_unreferenced_chunks=True)
                removed_manifest = True

            removed_chunks = manifest_store.delete_chunks_if_unreferenced(
                [str(chunk["hash"]) for chunk in deletion_manifest.chunks]
            )
            _sync_peer_connector_settings()
            return jsonify({
                "ok": True,
                "manifest_id": deletion_manifest.manifest_id,
                "removed_manifest": removed_manifest,
                "removed_chunks": removed_chunks,
                "state": state_payload(),
            })
        except (ValueError, TypeError, StorageError) as exc:
            return jsonify({"ok": False, "message": str(exc), "state": state_payload()}), 400

    @app.post("/api/p2p/manifests")
    def api_p2p_receive_manifest() -> Response:
        blocked = _reject_if_outgoing_only()
        if blocked is not None:
            return blocked
        try:
            data = request.get_json(force=True)
            if not isinstance(data, dict):
                raise StorageError("Manifest payload must be a JSON object")
            manifest = FileManifest.from_dict(data)
            if not manifest_store.may_access(manifest, identity.node_id):
                raise StorageError("Manifest is not shared with this node")
            if manifest_store.is_share_revoked(manifest.manifest_id, manifest.owner_node_id):
                raise StorageError("Manifest share has already been revoked")
            if manifest_store.is_file_deleted(manifest.manifest_id, manifest.owner_node_id):
                raise StorageError("Manifest has already been deleted by its owner")
            manifest_store.save_imported(manifest)
            return jsonify({"ok": True, "manifest_id": manifest.manifest_id, "state": state_payload()})
        except (ValueError, TypeError, StorageError) as exc:
            return jsonify({"ok": False, "message": str(exc), "state": state_payload()}), 400

    @app.post("/api/p2p/chat")
    def p2p_chat_message() -> Response:
        blocked = _reject_if_outgoing_only()
        if blocked is not None:
            return blocked
        payload = request.get_json(silent=True) or {}
        from_node_id = str(payload.get("from_node_id", "")).strip()
        to_node_id = str(payload.get("to_node_id", "")).strip()
        text = str(payload.get("text", "")).strip()
        if not from_node_id or not to_node_id or not text:
            return jsonify({"ok": False, "message": "Ungültige Chat-Nachricht"}), 400
        if to_node_id != identity.node_id:
            return jsonify({"ok": False, "message": "Nachricht war nicht für diesen Peer bestimmt"}), 400
        event = {
            "from_node_id": from_node_id,
            "to_node_id": to_node_id,
            "text": text,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "direction": "in",
        }
        chat_messages[from_node_id].append(event)
        return jsonify({"ok": True})

    @app.post("/files/<manifest_id>/delete")
    def delete_file(manifest_id: str) -> Response | str:
        redirect_target = _safe_next(request.form.get("next"), url_for("dashboard"))
        try:
            manifest = manifest_store.load(manifest_id)
            if manifest.owner_node_id == identity.node_id:
                cleanup = _delete_owned_manifest_with_peer_cleanup(manifest)
                if cleanup["delivered"]:
                    message = f"Datei gelöscht und bei {cleanup['delivered']} Peer(s) bereinigt: {manifest.file_name}"
                elif cleanup["target_count"]:
                    message = f"Datei gelöscht; Peer-Bereinigung wird nachgeholt, sobald die Peers erreichbar sind: {manifest.file_name}"
                else:
                    message = f"Datei gelöscht: {manifest.file_name}"
            else:
                manifest_store.delete(manifest.manifest_id, delete_unreferenced_chunks=True)
                message = f"Freigegebene Datei lokal entfernt: {manifest.file_name}"
            _remove_smb_virtual_file(manifest)
            if _is_ajax_request():
                return jsonify({"ok": True, "message": message, "state": state_payload()})
            flash(message, "success")
        except StorageError as exc:
            message = str(exc)
            if _is_ajax_request():
                return jsonify({"ok": False, "message": message, "state": state_payload()}), 400
            flash(message, "error")
        return redirect(redirect_target)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "node_id": identity.node_id}

    app.config["DCLOUD_STOP_RELAYS"] = _stop_relay_transport
    _configure_relay_transport()
    atexit.register(_stop_relay_transport)
    return app
