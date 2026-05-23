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
    DEFAULT_PUBLIC_RELAY_URLS,
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
    CHUNK_UPLOAD_PACK_MAGIC,
    P2PStorageClient,
    build_manifest_deletion,
    build_manifest_revocation,
    distribute_file_chunks,
    replicate_manifest_chunks,
    verify_manifest_deletion,
    verify_manifest_revocation,
)
from ..network.peers import Peer, PeerProvider, display_name_for_peer
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
) -> Flask:
    app = Flask(__name__)
    app.secret_key = identity.node_id[:32]
    app.config["DCLOUD_APP_CONFIG"] = config
    app.jinja_env.filters["human_bytes"] = human_bytes
    relay_clients: dict[str, HttpRelayClient] = {}
    relay_transports: dict[str, HttpRelayTransport] = {}
    relay_lock = threading.RLock()
    p2p_client = P2PStorageClient(default_web_port=config.web.port)
    upload_progress = UploadProgressTracker(persist_dir=chunk_store.tmp_dir / "upload_progress")
    download_progress = UploadProgressTracker(persist_dir=chunk_store.tmp_dir / "download_progress")
    download_results: dict[str, dict[str, Any]] = {}
    download_lock = threading.RLock()
    chat_messages: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=120))
    replication_repair_lock = threading.Lock()
    last_replication_repair_at = 0.0
    replication_queue: deque[dict[str, Any]] = deque()
    replication_queue_lock = threading.RLock()
    replication_queue_event = threading.Event()
    replication_worker_started = False
    replication_queued_manifest_ids: set[str] = set()

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
        # The local node must never appear as a share/storage target. If a relay or
        # stale discovery packet reports our own node id, sending a shared manifest
        # back to ourselves can resurrect old manifest ids and duplicate files.
        return [peer for peer in peer_provider.list_peers() if getattr(peer, "node_id", None) != identity.node_id]

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
        return True

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

    def _background_replication_progress(upload_id: str):
        def handle(event: dict[str, Any]) -> None:
            total_chunks = int(event.get("total_chunks") or 0)
            current_chunk = int(event.get("current_chunk") or 0)
            peer_percent = (current_chunk / total_chunks * 100.0) if total_chunks else 0.0
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
            fields["active"] = True
            fields["ok"] = None
            fields["percent"] = 100.0
            fields["server_percent"] = max(0.0, min(100.0, peer_percent))
            fields["details"] = {"backgroundReplication": True}
            upload_progress.update(upload_id, **fields)

        return handle

    def _ensure_replication_worker() -> None:
        nonlocal replication_worker_started
        with replication_queue_lock:
            if replication_worker_started:
                return
            replication_worker_started = True
        worker = threading.Thread(target=_replication_worker_loop, name="dcloud-background-replication", daemon=True)
        worker.start()

    def _enqueue_background_replication(
        manifest_id: str,
        *,
        upload_id: str | None = None,
        peer_node_ids: list[str] | None = None,
        file_name: str = "",
    ) -> bool:
        safe_manifest_id = str(manifest_id or "").strip()
        if not safe_manifest_id:
            return False
        with replication_queue_lock:
            if safe_manifest_id in replication_queued_manifest_ids:
                return False
            replication_queued_manifest_ids.add(safe_manifest_id)
            replication_queue.append({
                "manifest_id": safe_manifest_id,
                "upload_id": upload_id or "",
                "peer_node_ids": list(dict.fromkeys(str(item) for item in (peer_node_ids or []) if str(item))),
                "file_name": file_name,
                "queued_at": time.time(),
            })
            replication_queue_event.set()
        if upload_id:
            upload_progress.update(
                upload_id,
                active=True,
                ok=None,
                phase="background_replication_queued",
                status="Datei ist lokal gespeichert; Sicherheitskopie läuft im Hintergrund…",
                percent=100,
                server_percent=0,
                details={"backgroundReplication": True, "manifestId": safe_manifest_id},
            )
        _ensure_replication_worker()
        return True

    def _select_replication_peers(peer_node_ids: list[str] | None = None) -> list[Any]:
        active_peers = _eligible_storage_peers()
        wanted = {str(item) for item in (peer_node_ids or []) if str(item)}
        if not wanted:
            return active_peers
        selected = [peer for peer in active_peers if peer.node_id in wanted]
        return selected or active_peers

    def _process_background_replication_job(job: dict[str, Any]) -> None:
        manifest_id = str(job.get("manifest_id") or "")
        upload_id = str(job.get("upload_id") or "")
        file_name = str(job.get("file_name") or "")
        try:
            manifest = manifest_store.load(manifest_id)
            peers = _select_replication_peers(list(job.get("peer_node_ids") or []))
            if upload_id:
                upload_progress.update(
                    upload_id,
                    active=True,
                    ok=None,
                    phase="background_replication_start",
                    status="Upload ist abgeschlossen; Sicherheitskopien werden im Hintergrund verteilt…",
                    percent=100,
                    server_percent=0,
                    total_bytes=manifest.file_size,
                    total_chunks=len(manifest.chunks),
                    target_count=len(peers) + 1,
                    details={
                        "backgroundReplication": True,
                        "manifestId": manifest.manifest_id,
                        "peerTargets": [peer.to_dict().get("display_name") or peer.node_id[:12] for peer in peers],
                    },
                )
            result = replicate_manifest_chunks(
                manifest=manifest,
                chunk_store=chunk_store,
                local_node_id=identity.node_id,
                peers=peers,
                p2p_client=p2p_client,
                progress_callback=_background_replication_progress(upload_id) if upload_id else None,
            )
            placement = dict(manifest.placement or {})
            placement.update({
                "strategy": "local_first_background_replication",
                "target_count": len(result.targets),
                "targets": result.targets,
                "transfer_status": result.transfer_status,
                "remote_successes": result.remote_successes,
                "remote_failures": result.remote_failures,
                "local_chunks": result.local_chunks,
                "compressed_chunks": result.compressed_chunks,
                "desired_replicas": result.desired_replicas,
                "replicated_chunks": result.replicated_chunks,
                "under_replicated_chunks": result.under_replicated_chunks,
                "raw_bytes": result.raw_bytes,
                "stored_bytes": result.stored_bytes,
                "background_replication": False,
                "background_completed_at": datetime.now(timezone.utc).isoformat(),
            })
            updated_manifest = manifest_store.update_placement(
                manifest.manifest_id,
                identity,
                chunks=result.chunks,
                placement=placement,
            )
            if upload_id:
                if result.remote_successes:
                    message = (
                        f"Upload abgeschlossen: {file_name or manifest.file_name}; "
                        f"Sicherheitskopie im Hintergrund erstellt "
                        f"({result.replicated_chunks}/{len(result.chunks)} Chunks redundant)."
                    )
                elif peers:
                    message = (
                        f"Upload abgeschlossen: {file_name or manifest.file_name}; "
                        "Sicherheitskopie konnte noch nicht erstellt werden."
                    )
                else:
                    message = f"Upload abgeschlossen: {file_name or manifest.file_name}; keine Speicher-Peers aktiv."
                upload_progress.finish(
                    upload_id,
                    ok=True,
                    message=message,
                    details={
                        "backgroundReplication": True,
                        "manifestId": updated_manifest.manifest_id,
                        "transferStatus": result.transfer_status,
                        "replicatedChunks": result.replicated_chunks,
                        "underReplicatedChunks": result.under_replicated_chunks,
                    },
                )
        except Exception as exc:
            if upload_id:
                upload_progress.finish(
                    upload_id,
                    ok=True,
                    message=(
                        f"Upload abgeschlossen: {file_name or manifest_id}; "
                        f"Hintergrund-Replikation wird später erneut versucht ({exc})."
                    ),
                    details={"backgroundReplication": True, "replicationError": str(exc)},
                )

    def _replication_worker_loop() -> None:
        while True:
            replication_queue_event.wait()
            while True:
                with replication_queue_lock:
                    if not replication_queue:
                        replication_queue_event.clear()
                        break
                    job = replication_queue.popleft()
                manifest_id = str(job.get("manifest_id") or "")
                try:
                    _process_background_replication_job(job)
                finally:
                    with replication_queue_lock:
                        replication_queued_manifest_ids.discard(manifest_id)

    def _repair_under_replicated_manifests(peers: list[Any] | None = None, *, min_interval_seconds: float = 20.0) -> None:
        """Queue best-effort healing without doing network writes in a web request."""
        nonlocal last_replication_repair_at
        now = time.monotonic()
        if now - last_replication_repair_at < max(1.0, float(min_interval_seconds)):
            return
        if not replication_repair_lock.acquire(blocking=False):
            return
        try:
            last_replication_repair_at = now
            active_peers = _eligible_storage_peers(peers)
            if not active_peers:
                return
            peer_ids = [peer.node_id for peer in active_peers]
            for manifest in manifest_store.list_manifests():
                if manifest.owner_node_id != identity.node_id:
                    continue
                needs_replication = False
                for chunk in manifest.chunks:
                    existing_locations = [str(node_id) for node_id in chunk.get("locations", []) if str(node_id)]
                    remote_locations = [node_id for node_id in existing_locations if node_id != identity.node_id]
                    if not remote_locations and identity.node_id in existing_locations:
                        needs_replication = True
                        break
                if needs_replication:
                    _enqueue_background_replication(
                        manifest.manifest_id,
                        peer_node_ids=peer_ids,
                        file_name=manifest.file_name,
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
            "compressionMode": config.storage.compression.mode,
            "compressionAlgorithm": config.storage.compression.algorithm,
            "compressionLevel": config.storage.compression.level,
            "compressionMinSavingsPercent": config.storage.compression.min_savings_percent,
            "compressionMinSavingsBytes": config.storage.compression.min_savings_bytes,
            "compressionSkipIncompressible": bool(config.storage.compression.skip_incompressible),
            "compressionActiveLabel": (
                "Aus"
                if config.storage.compression.mode == "off"
                else f"{config.storage.compression.mode} · {config.storage.compression.algorithm} · Level {config.storage.compression.level}"
            ),
            "fixedRelayUrl": DEFAULT_PUBLIC_RELAY_URL,
            "fixedRelayUrls": DEFAULT_PUBLIC_RELAY_URLS.copy(),
            "fixedRelayUrlsText": "\n".join(DEFAULT_PUBLIC_RELAY_URLS),
            "relayUrl": config.network.relay_url,
            "relayUrls": list(config.network.relay_urls),
            "additionalRelayUrls": extra_relay_urls(config.network.relay_urls),
            "additionalRelayUrlsText": "\n".join(extra_relay_urls(config.network.relay_urls)),
            "relayEnabled": bool(config.network.relay_urls),
            "relaySecret": "",
            "relaySecretSet": False,
            "relayTokenMode": "automatic-daily",
            "relayTokenLabel": "Automatisch, tägliche Rotation",
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
                "fixed": url in DEFAULT_PUBLIC_RELAY_URLS,
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
        return {
            "udpHost": config.network.udp_host,
            "udpPort": config.network.udp_port,
            "autoDiscoveryEnabled": config.network.auto_discovery_enabled,
            "autoDiscoveryPorts": config.network.auto_discovery_ports,
            "autoDiscoveryHosts": config.network.auto_discovery_hosts,
            "discoveryIntervalSeconds": config.network.discovery_interval_seconds,
            "startupDiscoverySeconds": config.network.startup_discovery_seconds,
            "startupDiscoveryIntervalSeconds": config.network.startup_discovery_interval_seconds,
            "peerTimeoutSeconds": getattr(config.network, "peer_timeout_seconds", 35),
            "peerCleanupIntervalSeconds": getattr(config.network, "peer_cleanup_interval_seconds", 5),
            "fixedRelayUrl": DEFAULT_PUBLIC_RELAY_URL,
            "fixedRelayUrls": DEFAULT_PUBLIC_RELAY_URLS.copy(),
            "fixedRelayUrlsText": "\n".join(DEFAULT_PUBLIC_RELAY_URLS),
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
                    udp_port=config.network.udp_port,
                    web_port=config.web.port,
                    client_type=config.node.client_type,
                    shared_storage_bytes=config.storage.limit_bytes,
                    free_storage_bytes=chunk_store.stats().free_limit_bytes,
                    accepts_peer_storage=_accepts_peer_storage(_list_active_peers()),
                    poll_interval_seconds=getattr(config.network, "relay_poll_interval_seconds", 1),
                    peer_timeout_seconds=getattr(config.network, "peer_timeout_seconds", 35),
                    relay_urls=desired_urls,
                    relay_discovery_callback=_learn_relay_urls,
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

    def _local_first_upload_placement(upload_result: Any, storage_peers: list[Any]) -> dict[str, Any]:
        peer_ids = [peer.node_id for peer in storage_peers]
        targets = list(dict.fromkeys([identity.node_id, *peer_ids]))
        background_enabled = bool(storage_peers)
        return {
            "strategy": "local_first_background_replication",
            "target_count": len(targets),
            "targets": targets,
            "transfer_status": "background_replication_queued" if background_enabled else upload_result.transfer_status,
            "remote_successes": 0,
            "remote_failures": 0,
            "local_chunks": upload_result.local_chunks,
            "compressed_chunks": upload_result.compressed_chunks,
            "desired_replicas": 2 if background_enabled else 1,
            "replicated_chunks": 0,
            "under_replicated_chunks": len(upload_result.chunks) if background_enabled else 0,
            "raw_bytes": upload_result.raw_bytes,
            "stored_bytes": upload_result.stored_bytes,
            "background_replication": background_enabled,
            "background_queued_at": datetime.now(timezone.utc).isoformat() if background_enabled else None,
        }

    def _run_local_first_upload(
        *,
        temp_path: Path,
        safe_name: str,
        folder_path: str,
        upload_id: str,
        storage_peers: list[Any],
    ) -> tuple[FileManifest, Any, str]:
        file_size = temp_path.stat().st_size
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
        upload_progress.update(
            upload_id,
            phase="local_chunking",
            status="Datei wird lokal gespeichert; Peer-Verteilung startet danach im Hintergrund…",
            percent=45,
            server_percent=8,
            details={"backgroundReplication": bool(storage_peers)},
        )
        upload_result = distribute_file_chunks(
            source_path=temp_path,
            chunk_store=chunk_store,
            local_node_id=identity.node_id,
            peers=[],
            p2p_client=p2p_client,
            progress_callback=_upload_server_progress(upload_id),
            chunk_size_bytes=chunk_store.chunk_size,
        )
        placement = _local_first_upload_placement(upload_result, storage_peers)
        upload_progress.update(
            upload_id,
            phase="manifest",
            status="Lokales Manifest wird geschrieben; Datei ist danach sofort verfügbar…",
            percent=98,
            server_percent=95,
            raw_bytes_processed=upload_result.raw_bytes,
            stored_bytes=upload_result.stored_bytes,
            compressed_chunks=upload_result.compressed_chunks,
            local_chunks=upload_result.local_chunks,
            remote_successes=0,
            remote_failures=0,
            desired_replicas=placement["desired_replicas"],
            target_count=len(placement["targets"]),
            details={"backgroundReplication": bool(storage_peers)},
        )
        manifest = manifest_store.create_from_chunk_entries(
            file_name=safe_name,
            file_size=file_size,
            chunk_entries=upload_result.chunks,
            identity=identity,
            folder_path=folder_path,
            placement=placement,
        )
        if storage_peers:
            _enqueue_background_replication(
                manifest.manifest_id,
                upload_id=upload_id,
                peer_node_ids=[peer.node_id for peer in storage_peers],
                file_name=safe_name,
            )
            message = f"Datei lokal gespeichert: {safe_name}; Sicherheitskopie läuft im Hintergrund."
        else:
            message = f"Datei lokal gespeichert: {safe_name} in {folder_path} ({manifest.manifest_id[:12]})"
            upload_progress.finish(
                upload_id,
                ok=True,
                message=message,
                details={
                    "manifestId": manifest.manifest_id,
                    "transferStatus": upload_result.transfer_status,
                    "backgroundReplication": False,
                },
            )
        return manifest, upload_result, message

    def _store_uploaded_temp_file(temp_path: Path, safe_name: str, folder_path: str, upload_id: str, storage_peers: list[Any] | None = None) -> tuple[bool, dict[str, Any], int]:
        file_size = temp_path.stat().st_size
        _sync_peer_connector_settings()
        storage_peers = storage_peers if storage_peers is not None else _requested_storage_peers()
        manifest, upload_result, message = _run_local_first_upload(
            temp_path=temp_path,
            safe_name=safe_name,
            folder_path=folder_path,
            upload_id=upload_id,
            storage_peers=storage_peers,
        )
        return True, {"manifest": manifest, "upload_result": upload_result, "message": message}, file_size

    @app.post("/upload/smb")
    def upload_from_smb() -> Response:
        upload_id = _safe_upload_id(request.form.get("upload_id"))
        if SMBConnection is None:
            message = "SMB-Unterstuetzung ist nicht installiert (Python-Modul 'smb' fehlt)."
            upload_progress.finish(upload_id, ok=False, message=message)
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
            manifest, upload_result, message = _run_local_first_upload(
                temp_path=temp_path,
                safe_name=safe_name,
                folder_path=folder_path,
                upload_id=upload_id,
                storage_peers=storage_peers,
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
        peers = [peer for peer in _list_active_peers() if peer.node_id != identity.node_id]
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

            # Use the same fast binary batch path as background replication. The
            # old implementation used put_chunk() per chunk and then tried to
            # delete via delete_chunks_if_unreferenced(), which never removed the
            # local files because the offloaded manifest still references the
            # chunk hashes.
            result = replicate_manifest_chunks(
                manifest=manifest,
                chunk_store=chunk_store,
                local_node_id=identity.node_id,
                peers=peers,
                p2p_client=p2p_client,
                required_peer_node_ids=[target_peer_id] if target_peer_id else None,
            )

            updated_chunks: list[dict[str, Any]] = []
            removal_candidates: list[str] = []
            offloaded_location_count = 0
            local_kept_count = 0

            for chunk in result.chunks:
                entry = dict(chunk)
                digest = str(entry.get("hash") or "")
                locations = list(dict.fromkeys(str(value) for value in entry.get("locations", []) if str(value)))
                has_local = identity.node_id in locations
                remote_locations = [node_id for node_id in locations if node_id != identity.node_id]

                if add_only:
                    # Additional-node mode must never claim a local copy that is
                    # not actually present, but it also must not remove one.
                    entry["locations"] = locations or ([identity.node_id] if has_local else [])
                elif remote_locations and has_local:
                    # Offload only after at least one remote copy exists. From
                    # now on this manifest no longer requires the local chunk.
                    entry["locations"] = list(dict.fromkeys(remote_locations))
                    if digest:
                        removal_candidates.append(digest)
                    offloaded_location_count += 1
                else:
                    # Safety: keep local location when the remote write did not
                    # succeed. A missing local chunk is left untouched so existing
                    # remote-only manifests stay valid.
                    entry["locations"] = locations or ([identity.node_id] if has_local else [])
                    if has_local:
                        local_kept_count += 1
                updated_chunks.append(entry)

            new_targets = list(dict.fromkeys(location for chunk in updated_chunks for location in chunk.get("locations", [])))
            placement = dict(manifest.placement or {})
            placement.update({
                "strategy": "peer_additional_replica" if add_only else "peer_offload",
                "targets": new_targets,
                "target_count": len(new_targets),
                "transfer_status": "replicated_with_local_copy" if add_only else ("stored_on_peers" if removal_candidates else "local_only"),
                "offloaded_local_chunks": 0,
                "offload_requested_chunks": len(manifest.chunks),
                "offload_candidate_chunks": len(removal_candidates),
                "offload_remote_successes": result.remote_successes,
                "offload_remote_failures": result.remote_failures,
                "replicated_chunks": result.replicated_chunks,
                "under_replicated_chunks": result.under_replicated_chunks,
                "desired_replicas": result.desired_replicas,
                "local_chunks_kept": local_kept_count,
            })
            updated_manifest = manifest_store.update_placement(
                manifest.manifest_id,
                identity,
                chunks=updated_chunks,
                placement=placement,
            )

            local_removed = 0
            if removal_candidates and not add_only:
                local_removed = manifest_store.delete_local_chunks_if_unreferenced(removal_candidates, identity.node_id)
                placement["offloaded_local_chunks"] = local_removed
                placement["transfer_status"] = "stored_on_peers" if local_removed else "stored_on_peers_metadata_only"
                updated_manifest = manifest_store.update_placement(
                    updated_manifest.manifest_id,
                    identity,
                    placement=placement,
                )

            if add_only and result.remote_successes:
                message = f"Zusätzlicher Knoten erstellt: {result.remote_successes} Chunk-Kopie(n) auf Ziel-Peer übertragen (lokale Sicherheitskopie bleibt erhalten)"
            elif add_only:
                message = "Keine zusätzliche Kopie erstellt; lokale Daten bleiben unverändert erhalten"
            elif local_removed:
                message = f"Auslagerung abgeschlossen: {local_removed} lokale Chunk-Datei(en) entfernt, {offloaded_location_count} Chunk(s) liegen auf Peers"
            elif removal_candidates:
                message = "Auslagerung im Manifest abgeschlossen; lokale Chunk-Dateien werden noch von anderen lokalen Dateien benötigt"
            else:
                message = "Keine Chunks ausgelagert; es konnte noch keine Peer-Kopie erstellt werden"
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
                compression_mode=request.form.get("compression_mode", config.storage.compression.mode),
                compression_algorithm=request.form.get("compression_algorithm", config.storage.compression.algorithm),
                compression_level=request.form.get("compression_level", str(config.storage.compression.level)),
                compression_min_savings_percent=request.form.get("compression_min_savings_percent", str(config.storage.compression.min_savings_percent)),
                compression_skip_incompressible=request.form.get("compression_skip_incompressible") == "on",
            )
            chunk_store.limit_bytes = config.storage.limit_bytes
            chunk_store.configure_compression(
                mode=config.storage.compression.mode,
                algorithm=config.storage.compression.algorithm,
                level=config.storage.compression.level,
                min_savings_percent=config.storage.compression.min_savings_percent,
                min_savings_bytes=config.storage.compression.min_savings_bytes,
                skip_incompressible=config.storage.compression.skip_incompressible,
            )
            _configure_relay_transport()
            _sync_peer_connector_settings()
            relay_note = ", PHP-Relay deaktiviert" if not config.network.relay_urls else f", {len(config.network.relay_urls)} PHP-Relay(s) aktiv"
            message = (
                f"Einstellungen gespeichert: {client_type_label(config.node.client_type)}, "
                f"{bytes_to_gib(config.storage.limit_bytes):g} GB freigegeben{relay_note}, "
                f"Komprimierung {config.storage.compression.mode}/{config.storage.compression.algorithm}, "
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

    def _ensure_manifest_chunks_available(manifest: FileManifest, progress_callback: Any | None = None) -> None:
        peers_by_id = {peer.node_id: peer for peer in _list_active_peers()}
        all_peers = list(peers_by_id.values())
        chunks = sorted(manifest.chunks, key=lambda item: int(item["index"]))
        total_chunks = len(chunks)
        chunks_by_digest = {str(chunk["hash"]): chunk for chunk in chunks}
        missing: dict[str, dict[str, Any]] = {}

        for position, chunk in enumerate(chunks, start=1):
            digest = str(chunk["hash"])
            if progress_callback is not None:
                progress_callback(
                    {
                        "phase": "check_chunk",
                        "current_chunk": position,
                        "total_chunks": total_chunks,
                        "digest": digest,
                    }
                )
            if not chunk_store.chunk_path(digest).exists():
                missing[digest] = chunk

        if not missing:
            return

        missing_total = len(missing)
        restored_digests: set[str] = set()
        peer_candidates: dict[str, list[str]] = defaultdict(list)
        peer_order: list[str] = []

        for chunk in missing.values():
            digest = str(chunk["hash"])
            candidate_ids = [str(node_id) for node_id in chunk.get("locations", []) if str(node_id)]
            candidate_ids.extend(peer.node_id for peer in all_peers)
            seen: set[str] = set()
            for node_id in candidate_ids:
                if node_id == identity.node_id or node_id in seen or node_id not in peers_by_id:
                    continue
                seen.add(node_id)
                peer_candidates[node_id].append(digest)
                if node_id not in peer_order:
                    peer_order.append(node_id)

        def write_restored_chunk(digest: str, stored_data: bytes) -> bool:
            chunk = chunks_by_digest.get(digest)
            if chunk is None or chunk_store.chunk_path(digest).exists():
                return False
            chunk_store.write_stored_chunk(
                stored_data,
                original_size=int(chunk["size"]),
                index=int(chunk["index"]),
                compression=str(chunk.get("compression")) if chunk.get("compression") else None,
                digest=digest,
            )
            restored_digests.add(digest)
            missing.pop(digest, None)
            return True

        # Large files should not require one HTTP/PHP roundtrip per chunk.
        # Very large PHP-forwarded packs can still appear to hang because many
        # hosts buffer a full upstream response before the downloader sees any
        # bytes. Keep relay/forwarder blocks moderate and direct-LAN blocks
        # larger. Failed blocks are retried in smaller slices before the old
        # single-chunk fallback is used.
        def batch_limits_for_peer(peer: Peer) -> tuple[int, int, float]:
            if peer.host == RELAY_HOST:
                return 32, 16 * 1024 * 1024, 60.0
            return 96, 64 * 1024 * 1024, 90.0

        def emit_batch_progress(peer_name: str, batch_len: int, *, note: str = "") -> None:
            if progress_callback is None:
                return
            progress_callback(
                {
                    "phase": "fetch_chunk_batch",
                    "current_chunk": len(restored_digests),
                    "total_chunks": total_chunks,
                    "missing_chunks": len(missing),
                    "missing_total": missing_total,
                    "batch_size": batch_len,
                    "current_peer": peer_name,
                    "status_note": note,
                }
            )

        def fetch_and_store_batch(
            peer: Peer,
            peer_name: str,
            batch: list[str],
            *,
            max_chunks: int,
            max_payload_bytes: int,
            timeout: float,
            depth: int = 0,
        ) -> int:
            active_batch = [digest for digest in batch if digest in missing]
            if not active_batch:
                return 0
            note = "kleinerer Block" if depth else ""
            emit_batch_progress(peer_name, len(active_batch), note=note)
            try:
                received = p2p_client.get_chunks_batch(
                    peer,
                    digests=active_batch,
                    timeout=timeout,
                    max_chunks=max_chunks,
                    max_payload_bytes=max_payload_bytes,
                )
            except StorageError:
                received = {}
            stored_count = 0
            for received_digest, stored_data in received.items():
                if write_restored_chunk(received_digest, stored_data):
                    stored_count += 1
            if stored_count:
                emit_batch_progress(peer_name, stored_count, note="empfangen")
                return stored_count

            # Avoid leaving the UI at one big, stuck-looking block. Split a
            # failed batch a few times; the final single-chunk fallback below
            # remains available for very old peers.
            if len(active_batch) > 8 and depth < 3:
                midpoint = max(1, len(active_batch) // 2)
                emit_batch_progress(peer_name, len(active_batch), note="wird kleiner wiederholt")
                next_max_chunks = max(8, max_chunks // 2)
                next_max_payload = max(4 * 1024 * 1024, max_payload_bytes // 2)
                next_timeout = max(30.0, min(timeout, 45.0))
                left = fetch_and_store_batch(
                    peer,
                    peer_name,
                    active_batch[:midpoint],
                    max_chunks=next_max_chunks,
                    max_payload_bytes=next_max_payload,
                    timeout=next_timeout,
                    depth=depth + 1,
                )
                right = fetch_and_store_batch(
                    peer,
                    peer_name,
                    active_batch[midpoint:],
                    max_chunks=next_max_chunks,
                    max_payload_bytes=next_max_payload,
                    timeout=next_timeout,
                    depth=depth + 1,
                )
                return left + right
            return 0

        for node_id in peer_order:
            if not missing:
                break
            peer = peers_by_id.get(node_id)
            if peer is None:
                continue
            peer_name = peer.to_dict().get("display_name") or peer.node_id[:12]
            batch_size, batch_byte_budget, batch_timeout = batch_limits_for_peer(peer)
            candidate_digests = [digest for digest in peer_candidates.get(node_id, []) if digest in missing]
            batch: list[str] = []
            estimated_bytes = 0
            for digest in candidate_digests:
                if digest not in missing:
                    continue
                chunk = missing[digest]
                estimated_size = int(chunk.get("stored_size") or chunk.get("size") or 0)
                if batch and (len(batch) >= batch_size or estimated_bytes + estimated_size > batch_byte_budget):
                    fetch_and_store_batch(
                        peer,
                        peer_name,
                        batch,
                        max_chunks=batch_size,
                        max_payload_bytes=batch_byte_budget,
                        timeout=batch_timeout,
                    )
                    batch = []
                    estimated_bytes = 0
                batch.append(digest)
                estimated_bytes += estimated_size
            if batch:
                fetch_and_store_batch(
                    peer,
                    peer_name,
                    batch,
                    max_chunks=batch_size,
                    max_payload_bytes=batch_byte_budget,
                    timeout=batch_timeout,
                )

        # Conservative fallback: if a peer/server is older and does not know the
        # batch endpoint yet, still try the previous single-chunk API so mixed
        # versions keep working.
        for position, chunk in enumerate(chunks, start=1):
            digest = str(chunk["hash"])
            if digest not in missing:
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
                if progress_callback is not None:
                    progress_callback(
                        {
                            "phase": "fetch_chunk",
                            "current_chunk": position,
                            "total_chunks": total_chunks,
                            "digest": digest,
                            "current_peer": peer.to_dict().get("display_name") or peer.node_id[:12],
                        }
                    )
                try:
                    stored_data = p2p_client.get_chunk(peer, digest=digest)
                    restored = write_restored_chunk(digest, stored_data) or chunk_store.chunk_path(digest).exists()
                    if restored:
                        break
                except StorageError:
                    continue
            if not restored:
                raise StorageError(f"Chunk {digest[:12]} ist aktuell auf keinem aktiven Peer erreichbar")

    def _download_status_payload(download_id: str) -> dict[str, Any]:
        payload = download_progress.get(download_id)
        with download_lock:
            result = dict(download_results.get(download_id, {}))
        if result:
            details = dict(payload.get("details") or {})
            details.update(
                {
                    "downloadUrl": f"/api/downloads/{download_id}/file",
                    "fileName": result.get("file_name", ""),
                    "manifestId": result.get("manifest_id", ""),
                }
            )
            payload["details"] = details
        return payload

    def _download_progress_handler(download_id: str, manifest: FileManifest):
        total_chunks = max(1, len(manifest.chunks))

        def handle(event: dict[str, Any]) -> None:
            phase = str(event.get("phase") or "download")
            current_chunk = int(event.get("current_chunk") or 0)
            total = int(event.get("total_chunks") or total_chunks)
            if phase == "restore_chunk":
                server_percent = 60.0 + (current_chunk / max(1, total)) * 38.0
                status = f"Datei wird zusammengesetzt… Chunk {current_chunk}/{total}"
            elif phase == "fetch_chunk_batch":
                missing_chunks = int(event.get("missing_chunks") or 0)
                missing_total = int(event.get("missing_total") or missing_chunks or 1)
                fetched = max(0, missing_total - missing_chunks)
                batch_size = int(event.get("batch_size") or 0)
                server_percent = 18.0 + (fetched / max(1, missing_total)) * 40.0
                status = f"Fehlende Chunks werden in Blöcken geladen… {fetched}/{missing_total}"
                if batch_size:
                    status += f" (+{batch_size} Chunks)"
                status_note = str(event.get("status_note") or "").strip()
                if status_note:
                    status += f" · {status_note}"
            elif phase == "fetch_chunk":
                server_percent = 12.0 + ((max(0, current_chunk - 1) + 0.65) / max(1, total)) * 45.0
                status = f"Einzel-Fallback: fehlender Chunk wird geladen… {current_chunk}/{total}"
            else:
                server_percent = 8.0 + (current_chunk / max(1, total)) * 20.0
                status = f"Chunks werden geprüft… {current_chunk}/{total}"
            download_progress.update(
                download_id,
                phase=phase,
                status=status,
                percent=min(99.0, server_percent),
                server_percent=min(99.0, server_percent),
                total_bytes=manifest.file_size,
                raw_bytes_processed=int(event.get("raw_bytes_processed") or 0),
                current_chunk=current_chunk,
                total_chunks=total,
                current_peer=str(event.get("current_peer") or ""),
            )

        return handle

    def _prepare_download_background(download_id: str, manifest_id: str) -> None:
        try:
            manifest = manifest_store.load(manifest_id)
            if not manifest_store.may_access(manifest, identity.node_id):
                raise StorageError("Keine Berechtigung für diese Datei")
            progress_handler = _download_progress_handler(download_id, manifest)
            download_progress.update(
                download_id,
                phase="download_prepare",
                status="Download wird vorbereitet…",
                percent=3,
                server_percent=3,
                total_bytes=manifest.file_size,
                total_chunks=len(manifest.chunks),
                target_count=len({str(node_id) for chunk in manifest.chunks for node_id in chunk.get("locations", []) if str(node_id)}),
            )
            _ensure_manifest_chunks_available(manifest, progress_callback=progress_handler)
            safe_name = secure_filename(manifest.file_name) or "download.bin"
            output = chunk_store.downloads_dir / f"{download_id}-{safe_name}"
            manifest_store.restore(manifest.manifest_id, target=output, progress_callback=progress_handler)
            with download_lock:
                download_results[download_id] = {
                    "path": str(output),
                    "file_name": manifest.file_name,
                    "manifest_id": manifest.manifest_id,
                }
            download_progress.finish(
                download_id,
                ok=True,
                message="Download ist vorbereitet und startet jetzt.",
                details={"downloadUrl": f"/api/downloads/{download_id}/file"},
            )
        except Exception as exc:
            download_progress.finish(download_id, ok=False, message=str(exc))

    @app.post("/api/downloads/<manifest_id>/prepare")
    def api_prepare_download(manifest_id: str) -> Response:
        try:
            manifest = manifest_store.load(manifest_id)
            if not manifest_store.may_access(manifest, identity.node_id):
                return jsonify({"ok": False, "message": "Keine Berechtigung für diese Datei"}), 404
        except StorageError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 404
        download_id = _safe_upload_id(f"dl-{uuid4().hex}")
        download_progress.start(download_id, file_name=manifest.file_name, folder_path=manifest.folder_path, total_bytes=manifest.file_size)
        download_progress.update(
            download_id,
            phase="download_prepare",
            status="Download wird vorbereitet…",
            percent=1,
            server_percent=1,
            total_chunks=len(manifest.chunks),
        )
        thread = threading.Thread(target=_prepare_download_background, args=(download_id, manifest.manifest_id), daemon=True)
        thread.start()
        return jsonify({"ok": True, "downloadId": download_id, "progress": _download_status_payload(download_id)})

    @app.get("/api/downloads/<download_id>/status")
    def api_download_status(download_id: str) -> Response:
        return jsonify(_download_status_payload(_safe_upload_id(download_id)))

    @app.get("/api/downloads/<download_id>/file")
    def api_download_file(download_id: str) -> Response:
        safe_id = _safe_upload_id(download_id)
        progress = download_progress.get(safe_id)
        if not progress.get("ok"):
            abort(409, str(progress.get("message") or "Download ist noch nicht vorbereitet"))
        with download_lock:
            result = dict(download_results.get(safe_id, {}))
        path = Path(str(result.get("path") or ""))
        if not result or not path.exists():
            abort(404)
        return send_file(path, as_attachment=True, download_name=str(result.get("file_name") or path.name))

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
        try:
            data = chunk_store.read_stored_chunk(digest)
        except StorageError:
            abort(404)
        return Response(data, mimetype="application/octet-stream")

    def _chunk_batch_payload_from_request() -> dict[str, Any]:
        payload = request.get_json(force=True)
        return payload if isinstance(payload, dict) else {}

    def _chunk_batch_digests_from_payload(payload: dict[str, Any]) -> list[str]:
        raw_digests = payload.get("digests", [])
        if not isinstance(raw_digests, list) or not raw_digests:
            raise StorageError("Batch payload must include at least one digest")
        return list(dict.fromkeys(str(digest).strip() for digest in raw_digests if str(digest).strip()))

    def _chunk_batch_limit(payload: dict[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
        try:
            value = int(payload.get(key) or default)
        except (TypeError, ValueError):
            value = default
        return max(minimum, min(maximum, value))

    @app.post("/api/p2p/chunks/batch/pack")
    def api_p2p_get_chunks_pack() -> Response:
        try:
            payload = _chunk_batch_payload_from_request()
            digests = _chunk_batch_digests_from_payload(payload)
        except (ValueError, StorageError, TypeError) as exc:
            return jsonify({"ok": False, "message": str(exc), "state": state_payload()}), 400

        max_chunks = _chunk_batch_limit(payload, "max_chunks", 128, 1, 128)
        max_payload_bytes = _chunk_batch_limit(payload, "max_payload_bytes", 96 * 1024 * 1024, 1024 * 1024, 96 * 1024 * 1024)
        pack_magic = b"DCLOUD-CHUNK-PACK-1\n"

        def generate():
            yielded = 0
            payload_bytes = 0
            yield pack_magic
            for digest in digests:
                if yielded >= max_chunks:
                    break
                try:
                    data = chunk_store.read_stored_chunk(digest)
                except StorageError:
                    continue
                if yielded and payload_bytes + len(data) > max_payload_bytes:
                    break
                header = f"{digest} {len(data)}\n".encode("ascii", errors="strict")
                yield header
                yield data
                yielded += 1
                payload_bytes += len(data)

        return Response(
            generate(),
            mimetype="application/octet-stream",
            headers={
                "X-DCloud-Pack-Format": "chunk-pack-v1",
                "X-DCloud-Max-Chunks": str(max_chunks),
                "X-DCloud-Max-Payload-Bytes": str(max_payload_bytes),
            },
        )

    @app.post("/api/p2p/chunks/batch/download")
    def api_p2p_get_chunks_batch() -> Response:
        try:
            payload = _chunk_batch_payload_from_request()
            digests = _chunk_batch_digests_from_payload(payload)
            max_chunks = _chunk_batch_limit(payload, "max_chunks", 128, 1, 128)
            max_payload_bytes = _chunk_batch_limit(payload, "max_payload_bytes", 96 * 1024 * 1024, 1024 * 1024, 96 * 1024 * 1024)
            chunks_payload: list[dict[str, Any]] = []
            missing: list[str] = []
            payload_bytes = 0
            truncated = False
            for digest in digests:
                if len(chunks_payload) >= max_chunks:
                    truncated = True
                    break
                try:
                    data = chunk_store.read_stored_chunk(digest)
                except StorageError:
                    missing.append(digest)
                    continue
                if chunks_payload and payload_bytes + len(data) > max_payload_bytes:
                    truncated = True
                    break
                chunks_payload.append(
                    {
                        "digest": digest,
                        "stored_size": len(data),
                        "stored_data_b64": base64.b64encode(data).decode("ascii"),
                    }
                )
                payload_bytes += len(data)
            return jsonify(
                {
                    "ok": True,
                    "chunks": chunks_payload,
                    "returned_count": len(chunks_payload),
                    "requested_count": len(digests),
                    "missing": missing,
                    "truncated": truncated,
                    "payload_bytes": payload_bytes,
                    "state": state_payload(),
                }
            )
        except (ValueError, StorageError, TypeError) as exc:
            return jsonify({"ok": False, "message": str(exc), "state": state_payload()}), 400

    @app.post("/api/p2p/chunks/<digest>")
    def api_p2p_put_chunk(digest: str) -> Response:
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

    def _parse_chunk_upload_pack(body: bytes) -> list[dict[str, Any]]:
        if not body.startswith(CHUNK_UPLOAD_PACK_MAGIC):
            raise StorageError("Ungültiges Chunk-Upload-Pack")
        offset = len(CHUNK_UPLOAD_PACK_MAGIC)
        chunks: list[dict[str, Any]] = []
        while offset < len(body):
            line_end = body.find(b"\n", offset)
            if line_end < 0:
                raise StorageError("Chunk-Upload-Pack ist unvollständig")
            line = body[offset:line_end].decode("ascii", errors="strict").strip()
            offset = line_end + 1
            if not line:
                continue
            parts = line.split(" ")
            if len(parts) != 5:
                raise StorageError("Chunk-Upload-Pack enthält ungültige Metadaten")
            digest, original_size_raw, stored_size_raw, index_raw, compression_raw = parts
            original_size = int(original_size_raw)
            stored_size = int(stored_size_raw)
            index = int(index_raw)
            if original_size <= 0 or stored_size < 0:
                raise StorageError("Chunk-Upload-Pack enthält ungültige Größen")
            end = offset + stored_size
            if end > len(body):
                raise StorageError("Chunk-Upload-Pack Nutzdaten sind unvollständig")
            chunks.append(
                {
                    "digest": digest,
                    "original_size": original_size,
                    "stored_size": stored_size,
                    "index": index,
                    "compression": None if compression_raw == "-" else compression_raw,
                    "data": body[offset:end],
                }
            )
            offset = end
        if not chunks:
            raise StorageError("Chunk-Upload-Pack enthält keine Chunks")
        return chunks

    @app.post("/api/p2p/chunks/batch/pack/upload")
    def api_p2p_put_chunks_pack() -> Response:
        try:
            chunks = _parse_chunk_upload_pack(request.get_data())
            stored: list[str] = []
            for item in chunks:
                info = chunk_store.write_stored_chunk(
                    item["data"],
                    original_size=int(item["original_size"]),
                    index=int(item["index"]),
                    compression=item.get("compression"),
                    digest=str(item["digest"]),
                )
                stored.append(info.hash)
            _sync_peer_connector_settings()
            return jsonify({"ok": True, "stored": stored, "stored_count": len(stored), "state": state_payload()})
        except (ValueError, TypeError, UnicodeDecodeError, StorageError) as exc:
            return jsonify({"ok": False, "message": str(exc), "state": state_payload()}), 400

    @app.post("/api/p2p/chunks/batch")
    def api_p2p_put_chunks_batch() -> Response:
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
            if manifest.owner_node_id == identity.node_id:
                return jsonify({"ok": True, "manifest_id": manifest.manifest_id, "ignored": "own_manifest", "state": state_payload()})
            manifest_store.save_imported(manifest)
            return jsonify({"ok": True, "manifest_id": manifest.manifest_id, "state": state_payload()})
        except (ValueError, TypeError, StorageError) as exc:
            return jsonify({"ok": False, "message": str(exc), "state": state_payload()}), 400

    @app.post("/api/p2p/chat")
    def p2p_chat_message() -> Response:
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
