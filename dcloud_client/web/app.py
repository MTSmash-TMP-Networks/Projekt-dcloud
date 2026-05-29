"""Flask application for the local-only MVP web UI."""

from __future__ import annotations

from pathlib import Path
import os
import sys
import logging
import tempfile
import json
import secrets
import csv
import html
import mimetypes
import zipfile
import xml.etree.ElementTree as ET
from typing import Any, Protocol
from io import BytesIO
import threading
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from uuid import uuid4
import atexit
import base64
import socket
import ipaddress
import time
import subprocess
import re
import shutil
import unicodedata
from urllib import error as url_error, parse as url_parse, request as url_request
import http.cookiejar

try:
    import psutil  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - optional dependency fallback
    psutil = None  # type: ignore[assignment]

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.utils import secure_filename

from ..config import (
    AppConfig,
    MIN_SHARED_STORAGE_GB,
    bytes_to_gib,
    client_type_label,
    update_runtime_settings,
)
from ..identity import IdentityManager, NodeIdentity, build_backup_token
from ..crypto import b64decode, derive_node_id, sha256_hex, verify_signature
from ..manifests import DEFAULT_FOLDER, INCOMING_SHARES_FOLDER, REMOTE_DELETE_GRACE_SECONDS, FileManifest, ManifestStore, sanitize_folder_path
from ..network.p2p_storage import (
    CHUNK_UPLOAD_PACK_MAGIC,
    P2PStorageClient,
    build_manifest_deletion,
    build_manifest_revocation,
    distribute_file_chunks,
    dynamic_mirror_replica_count,
    rank_peers_by_speed,
    replicate_manifest_chunks,
    verify_manifest_deletion,
    verify_manifest_revocation,
)
from ..network.peers import Peer, PeerProvider, display_name_for_peer, normalize_public_urls
from ..storage import ChunkStore, StorageError, StorageStats
from .upload_progress import UploadProgressTracker
from .auth import UserStore


class PeerConnector(Protocol):
    def add_peer_address(self, host: str, port: int, *, use_as_tree_parent: bool = False) -> None: ...
    def announce_once(self) -> None: ...
    def prune_stale_peers(self) -> list[str]: ...


WEB_EXPLORER_FOLDER = "web"
BROWSER_DOWNLOADS_FOLDER = "Downloads"


RELAY_HOST = "__relay__"


class RelayHttpResponse:
    """Compatibility response used by removed relay-only helper code paths."""
    def __init__(self, status_code: int, headers: dict[str, str] | None = None, body: bytes = b"") -> None:
        self.status_code = int(status_code)
        self.headers = headers or {}
        self.body = body


class HttpRelayClient:
    """Removed PHP relay placeholder; direct peer endpoints are required."""
    pass


class HttpRelayTransport:
    """Removed PHP relay placeholder."""
    pass

BROWSER_DOWNLOAD_CONTENT_EXTENSIONS = {
    ".7z", ".apk", ".bin", ".bz2", ".dmg", ".doc", ".docx", ".exe", ".gz",
    ".iso", ".msi", ".odt", ".ods", ".pdf", ".ppt", ".pptx", ".rar",
    ".tar", ".tgz", ".xls", ".xlsx", ".zip", ".zst",
}
BROWSER_DOWNLOAD_INTERNAL_ARTIFACT_RE = re.compile(r"^f(?:-\d+)?\.txt$", re.IGNORECASE)
WEB_EDITABLE_SUFFIXES = {
    ".html", ".htm", ".php", ".css", ".js", ".mjs", ".json", ".txt",
    ".md", ".xml", ".svg", ".csv", ".yml", ".yaml", ".ini", ".env",
    ".py", ".sh", ".bat", ".ps1", ".sql", ".rss", ".atom",
}
WEB_EDIT_MAX_BYTES = 2 * 1024 * 1024
NETWORK_LOAD_HISTORY_LIMIT = 72
NETWORK_LOAD_MIN_SAMPLE_SECONDS = 1.0
LARGE_UPLOAD_THRESHOLD_BYTES = int(os.environ.get("DCLOUD_LARGE_UPLOAD_THRESHOLD_BYTES", str(64 * 1024 * 1024)))
LARGE_UPLOAD_CHUNK_BYTES = int(os.environ.get("DCLOUD_UPLOAD_CHUNK_BYTES", str(16 * 1024 * 1024)))
LARGE_UPLOAD_MAX_BYTES = int(os.environ.get("DCLOUD_LARGE_UPLOAD_MAX_BYTES", str(64 * 1024 * 1024 * 1024)))
LARGE_UPLOAD_STREAM_BUFFER_BYTES = int(os.environ.get("DCLOUD_UPLOAD_STREAM_BUFFER_BYTES", str(1024 * 1024)))
LOG = logging.getLogger(__name__)


def _read_system_net_io() -> tuple[int, int] | None:
    """Return cumulative sent/received bytes for the host network interfaces."""
    if psutil is not None:
        try:
            counters = psutil.net_io_counters(pernic=False)
            if counters is not None:
                return int(getattr(counters, "bytes_sent", 0)), int(getattr(counters, "bytes_recv", 0))
        except Exception:
            pass

    proc_net_dev = Path("/proc/net/dev")
    try:
        lines = proc_net_dev.read_text(encoding="utf-8", errors="replace").splitlines()[2:]
    except Exception:
        return None

    sent = 0
    received = 0
    for line in lines:
        if ":" not in line:
            continue
        iface, raw_values = line.split(":", 1)
        if iface.strip() == "lo":
            continue
        values = raw_values.split()
        if len(values) < 16:
            continue
        try:
            received += int(values[0])
            sent += int(values[8])
        except ValueError:
            continue
    return sent, received


class NetworkLoadSampler:
    """Small in-memory sampler for the dashboard network load graph."""

    def __init__(self, *, history_limit: int = NETWORK_LOAD_HISTORY_LIMIT) -> None:
        self._history: deque[dict[str, Any]] = deque(maxlen=history_limit)
        self._last_counter: tuple[float, int, int] | None = None
        self._last_payload: dict[str, Any] | None = None
        self._last_sample_at = 0.0
        self._lock = threading.RLock()

    def sample(self, *, peer_count: int) -> dict[str, Any]:
        with self._lock:
            now = time.monotonic()
            if self._last_payload is not None and now - self._last_sample_at < NETWORK_LOAD_MIN_SAMPLE_SECONDS:
                payload = dict(self._last_payload)
                payload["peerCount"] = int(peer_count)
                return payload

            counters = _read_system_net_io()
            timestamp_ms = int(time.time() * 1000)
            if counters is None:
                payload = {
                    "available": False,
                    "message": "Netzwerklast konnte auf diesem System nicht gelesen werden.",
                    "uploadBps": 0,
                    "downloadBps": 0,
                    "totalBps": 0,
                    "perPeerBps": 0,
                    "peerCount": int(peer_count),
                    "history": list(self._history),
                }
                self._last_payload = payload
                self._last_sample_at = now
                return payload

            sent, received = counters
            upload_bps = 0.0
            download_bps = 0.0
            interval = 0.0
            if self._last_counter is not None:
                last_time, last_sent, last_received = self._last_counter
                interval = max(0.001, now - last_time)
                sent_delta = max(0, sent - last_sent)
                received_delta = max(0, received - last_received)
                upload_bps = sent_delta / interval
                download_bps = received_delta / interval

            self._last_counter = (now, sent, received)
            self._last_sample_at = now
            total_bps = upload_bps + download_bps
            per_peer_bps = total_bps / max(1, int(peer_count))
            sample = {
                "timeMs": timestamp_ms,
                "uploadBps": round(upload_bps, 2),
                "downloadBps": round(download_bps, 2),
                "totalBps": round(total_bps, 2),
                "perPeerBps": round(per_peer_bps, 2),
                "peerCount": int(peer_count),
            }
            self._history.append(sample)
            payload = {
                "available": True,
                "message": "Host-Netzwerklast über alle aktiven Interfaces.",
                "uploadBps": sample["uploadBps"],
                "downloadBps": sample["downloadBps"],
                "totalBps": sample["totalBps"],
                "perPeerBps": sample["perPeerBps"],
                "peerCount": int(peer_count),
                "sentBytes": int(sent),
                "receivedBytes": int(received),
                "sampleIntervalSeconds": round(interval, 2),
                "history": list(self._history),
            }
            self._last_payload = payload
            return payload


def human_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{value} B"




def current_git_revision() -> str:
    """Return the best available source-code revision for the dashboard."""
    for env_name in ("DCLOUD_GIT_REVISION", "GIT_COMMIT", "SOURCE_COMMIT"):
        value = os.environ.get(env_name, "").strip()
        if value and value.lower() not in {"unknown", "unbekannt", "none", "null"}:
            return value[:12]

    for marker in (Path("/app/.dcloud_git_revision"), Path(__file__).resolve().parents[2] / ".dcloud_git_revision"):
        try:
            value = marker.read_text(encoding="utf-8").strip()
        except Exception:
            continue
        if value and value.lower() not in {"unknown", "unbekannt", "none", "null"}:
            return value[:12]

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(Path(__file__).resolve().parents[2]),
            capture_output=True,
            text=True,
            check=True,
        )
        revision = result.stdout.strip()
        return revision or "unbekannt"
    except Exception:
        return "unbekannt"


def _restart_current_process_delayed(delay_seconds: float = 0.8) -> None:
    """Restart the running dcloud process after the HTTP response has been sent."""

    def restart_worker() -> None:
        time.sleep(delay_seconds)
        command = [sys.executable, *sys.argv]
        try:
            os.chdir(str(Path.cwd()))
        except Exception:
            pass
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        os.execv(sys.executable, command)

    thread = threading.Thread(target=restart_worker, name="dcloud-self-restart", daemon=True)
    thread.start()

def _tail_text_file(path: Path, *, max_lines: int = 120, max_chars: int = 12000) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
        text = "".join(lines[-max_lines:])
        return text[-max_chars:] if len(text) > max_chars else text
    except Exception:
        return ""


def display_folder_for_node(manifest: FileManifest, node_id: str) -> str:
    """Return the UI folder for a manifest from the current node's perspective."""
    return sanitize_folder_path(manifest.folder_path) if manifest.owner_node_id == node_id else INCOMING_SHARES_FOLDER


def build_folder_tree(
    manifests: list[FileManifest],
    folders: list[str] | None = None,
    current_node_id: str | None = None,
) -> list[dict[str, object]]:
    """Group manifests into virtual folders for the Dashboard explorer."""
    grouped: dict[str, list[FileManifest]] = {sanitize_folder_path(folder): [] for folder in (folders or [DEFAULT_FOLDER, INCOMING_SHARES_FOLDER])}
    for manifest in manifests:
        folder = display_folder_for_node(manifest, current_node_id or manifest.owner_node_id)
        grouped.setdefault(folder, []).append(manifest)
    grouped.setdefault(DEFAULT_FOLDER, [])
    grouped.setdefault(INCOMING_SHARES_FOLDER, [])
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
    def _load_or_create_dashboard_secret() -> str:
        secret_path = chunk_store.root / "security" / "dashboard_secret.key"
        try:
            secret_path.parent.mkdir(parents=True, exist_ok=True)
            if secret_path.exists():
                value = secret_path.read_text(encoding="utf-8").strip()
                if len(value) >= 32:
                    return value
            value = secrets.token_urlsafe(48)
            tmp_path = secret_path.with_suffix(".tmp")
            tmp_path.write_text(value, encoding="utf-8")
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            tmp_path.replace(secret_path)
            return value
        except Exception:
            # Last-resort fallback keeps the dashboard running, but persistent
            # installations should always be able to write the secret file.
            return secrets.token_urlsafe(48)

    class _NoRedirectHandler(url_request.HTTPRedirectHandler):
        def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:  # type: ignore[override]
            return None

    app = Flask(__name__)
    app.secret_key = _load_or_create_dashboard_secret()
    app.config.update(
        DCLOUD_APP_CONFIG=config,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=str(os.environ.get("DCLOUD_COOKIE_SECURE", "")).lower() in {"1", "true", "yes", "on"},
        MAX_CONTENT_LENGTH=int(os.environ.get("DCLOUD_MAX_REQUEST_BYTES", str(1024 * 1024 * 1024))),
    )
    app.jinja_env.filters["human_bytes"] = human_bytes
    browser_access_token = secrets.token_urlsafe(32)
    browser_cookie_jar = http.cookiejar.CookieJar()
    browser_http_opener = url_request.build_opener(_NoRedirectHandler, url_request.HTTPCookieProcessor(browser_cookie_jar))
    relay_clients: dict[str, Any] = {}
    relay_transports: dict[str, Any] = {}
    relay_lock = threading.RLock()
    allow_relay_data_transfer = False
    p2p_client = P2PStorageClient(default_web_port=config.web.port, identity=identity, allow_relay_data=False)
    upload_progress = UploadProgressTracker(
        persist_dir=chunk_store.tmp_dir / "upload_progress",
        active_stall_seconds=int(os.environ.get("DCLOUD_UPLOAD_STALL_SECONDS", "900")),
    )
    large_upload_sessions_dir = chunk_store.tmp_dir / "upload_sessions"
    large_upload_sessions_dir.mkdir(parents=True, exist_ok=True)
    large_upload_session_lock = threading.RLock()
    download_progress = UploadProgressTracker(persist_dir=chunk_store.tmp_dir / "download_progress")
    network_load_sampler = NetworkLoadSampler()
    download_results: dict[str, dict[str, Any]] = {}
    download_lock = threading.RLock()
    external_link_lock = threading.RLock()
    external_links_path = chunk_store.tmp_dir / "external_download_links.json"
    external_download_links: dict[str, dict[str, Any]] = {}
    disabled_peer_lock = threading.RLock()
    disabled_peers_path = chunk_store.root / "disabled_peers.json"
    disabled_peers: dict[str, dict[str, Any]] = {}
    manual_peer_routes_path = chunk_store.root / "manual_peer_routes.json"
    manual_peer_routes: dict[str, dict[str, Any]] = {}
    manual_peer_routes_lock = threading.RLock()
    last_manual_peer_route_refresh_at = 0.0
    chat_messages: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=240))
    chat_unread: dict[str, int] = defaultdict(int)
    chat_lock = threading.RLock()
    chat_delivery_queue: deque[dict[str, Any]] = deque()
    chat_delivery_event = threading.Event()
    chat_delivery_lock = threading.RLock()
    chat_delivery_worker_started = False
    chat_settings_path = chunk_store.root / "chat_settings.json"
    chat_settings: dict[str, Any] = {"enabled": True, "alias": ""}
    replication_repair_lock = threading.Lock()
    last_replication_repair_at = 0.0
    replication_queue: deque[dict[str, Any]] = deque()
    replication_queue_lock = threading.RLock()
    replication_queue_event = threading.Event()
    replication_worker_started = False
    replication_queued_manifest_ids: set[str] = set()
    file_deletion_delivery_lock = threading.Lock()
    file_deletion_delivery_event = threading.Event()
    file_deletion_delivery_worker_started = False
    last_file_deletion_delivery_enqueue_at = 0.0
    share_delivery_lock = threading.Lock()
    share_delivery_attempts: dict[str, float] = {}
    incoming_share_sync_lock = threading.Lock()
    incoming_share_sync_attempts: dict[str, float] = {}
    SHARE_DELIVERY_RETRY_SECONDS = int(os.environ.get("DCLOUD_SHARE_DELIVERY_RETRY_SECONDS", "120"))
    SHARE_DELIVERY_SUCCESS_REFRESH_SECONDS = int(os.environ.get("DCLOUD_SHARE_DELIVERY_SUCCESS_REFRESH_SECONDS", "1800"))
    SHARE_DELIVERY_MAX_PER_PASS = int(os.environ.get("DCLOUD_SHARE_DELIVERY_MAX_PER_PASS", "12"))
    INCOMING_SHARE_SYNC_SECONDS = int(os.environ.get("DCLOUD_INCOMING_SHARE_SYNC_SECONDS", "60"))
    INCOMING_SHARE_SYNC_MAX_PEERS_PER_PASS = int(os.environ.get("DCLOUD_INCOMING_SHARE_SYNC_MAX_PEERS_PER_PASS", "4"))
    user_store = UserStore(chunk_store.root / "users.json")
    web_root = chunk_store.root / "web"
    browser_downloads_root = chunk_store.root / BROWSER_DOWNLOADS_FOLDER
    p2p_nonce_lock = threading.RLock()
    p2p_seen_nonces: dict[str, float] = {}
    p2p_rate_lock = threading.RLock()
    p2p_rate_buckets: dict[str, deque[float]] = defaultdict(deque)
    MAX_P2P_REQUEST_BYTES = 80 * 1024 * 1024
    P2P_SIGNATURE_WINDOW_SECONDS = 300
    P2P_NONCE_RETENTION_SECONDS = 900
    P2P_RATE_WINDOW_SECONDS = 60
    P2P_RATE_MAX_REQUESTS = 420

    def _csrf_token() -> str:
        token = session.get("dcloud_csrf_token")
        if not isinstance(token, str) or len(token) < 24:
            token = secrets.token_urlsafe(32)
            session["dcloud_csrf_token"] = token
        return token

    def _csrf_error(message: str = "Sicherheitsprüfung fehlgeschlagen. Bitte Dashboard neu laden.") -> Response:
        if _wants_json_response():
            return jsonify({"ok": False, "message": message}), 403
        return Response(message, status=403, content_type="text/plain; charset=utf-8")

    def _normalize_origin(value: str) -> str | None:
        value = (value or "").strip()
        if not value or value == "null":
            return None
        try:
            parsed = url_parse.urlsplit(value)
        except Exception:
            return None
        if not parsed.scheme or not parsed.netloc:
            return None
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host:
            return None
        port = parsed.port
        default_port = 443 if scheme == "https" else 80
        netloc = host if port in (None, default_port) else f"{host}:{port}"
        return f"{scheme}://{netloc}"

    def _dashboard_allowed_origins() -> set[str]:
        origins: set[str] = set()

        def add(value: str | None) -> None:
            normalized = _normalize_origin(value or "")
            if normalized:
                origins.add(normalized)

        add(request.host_url.rstrip("/"))

        host = (request.headers.get("Host") or request.host or "").split(",", 1)[0].strip()
        proto = (request.headers.get("X-Forwarded-Proto") or request.scheme or "http").split(",", 1)[0].strip()
        if host:
            add(f"{proto}://{host}")

        forwarded_host = (request.headers.get("X-Forwarded-Host") or "").split(",", 1)[0].strip()
        forwarded_proto = (request.headers.get("X-Forwarded-Proto") or proto or "http").split(",", 1)[0].strip()
        if forwarded_host:
            add(f"{forwarded_proto}://{forwarded_host}")

        forwarded = request.headers.get("Forwarded") or ""
        if forwarded:
            first = forwarded.split(",", 1)[0]
            forwarded_parts: dict[str, str] = {}
            for part in first.split(";"):
                if "=" not in part:
                    continue
                key, value = part.split("=", 1)
                forwarded_parts[key.strip().lower()] = value.strip().strip('"')
            if forwarded_parts.get("host"):
                add(f"{forwarded_parts.get('proto') or proto or 'http'}://{forwarded_parts['host']}")

        for env_name in ("DCLOUD_DASHBOARD_PUBLIC_URL", "DCLOUD_DASHBOARD_ALLOWED_ORIGINS", "DCLOUD_TRUSTED_ORIGINS"):
            raw = os.environ.get(env_name, "")
            for item in re.split(r"[\s,;]+", raw):
                add(item)
        return origins

    def _same_origin_or_empty() -> bool:
        origin = request.headers.get("Origin") or ""
        referer = request.headers.get("Referer") or ""
        if not origin and not referer:
            return True
        # Prefer the Origin header when present. Referer is only a fallback because
        # many browsers and privacy tools intentionally strip or shorten it.
        values = [origin] if origin else [referer]
        allowed = _dashboard_allowed_origins()
        for value in values:
            candidate = _normalize_origin(value)
            if candidate and candidate in allowed:
                return True
        return False

    def _csrf_exempt_path(path: str) -> bool:
        if request.method == "OPTIONS":
            return True
        if path.startswith("/api/p2p/"):
            return True
        if path.startswith("/dcloud-site"):
            return True
        if path.startswith("/external/"):
            return True
        if path.startswith("/browser/view"):
            token = str(request.args.get("browser_token") or "")
            return bool(token and secrets.compare_digest(token, browser_access_token))
        return False

    def _check_csrf_for_dashboard_request(path: str) -> Response | None:
        if request.method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
            return None
        if _csrf_exempt_path(path):
            return None
        expected = str(session.get("dcloud_csrf_token") or "")
        provided = str(
            request.headers.get("X-CSRF-Token")
            or request.headers.get("X-DCloud-CSRF")
            or request.form.get("csrf_token")
            or request.args.get("csrf_token")
            or ""
        )
        token_ok = bool(expected and provided and secrets.compare_digest(expected, provided))
        if not token_ok:
            if not _same_origin_or_empty():
                return _csrf_error("Anfrage wurde wegen ungültiger Herkunft blockiert.")
            return _csrf_error()
        return None

    def _cleanup_p2p_security_state(now: float) -> None:
        cutoff_nonce = now - P2P_NONCE_RETENTION_SECONDS
        with p2p_nonce_lock:
            for key, seen_at in list(p2p_seen_nonces.items()):
                if seen_at < cutoff_nonce:
                    p2p_seen_nonces.pop(key, None)
        cutoff_rate = now - P2P_RATE_WINDOW_SECONDS
        with p2p_rate_lock:
            for key, bucket in list(p2p_rate_buckets.items()):
                while bucket and bucket[0] < cutoff_rate:
                    bucket.popleft()
                if not bucket:
                    p2p_rate_buckets.pop(key, None)

    def _p2p_rate_limit_key() -> str:
        forwarded = request.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
        return forwarded or request.remote_addr or "unknown"

    def _check_p2p_rate_limit() -> Response | None:
        now = time.time()
        _cleanup_p2p_security_state(now)
        key = _p2p_rate_limit_key()
        with p2p_rate_lock:
            bucket = p2p_rate_buckets[key]
            cutoff = now - P2P_RATE_WINDOW_SECONDS
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= P2P_RATE_MAX_REQUESTS:
                return jsonify({"ok": False, "message": "P2P-Rate-Limit erreicht"}), 429
            bucket.append(now)
        return None

    def _p2p_signature_error(message: str, status: int = 403) -> Response:
        return jsonify({"ok": False, "message": message}), status

    def _verify_p2p_request_signature() -> Response | None:
        if not request.path.startswith("/api/p2p/"):
            return None
        limited = _check_p2p_rate_limit()
        if limited is not None:
            return limited
        try:
            content_length = int(request.headers.get("Content-Length") or 0)
        except ValueError:
            content_length = 0
        if content_length > MAX_P2P_REQUEST_BYTES:
            return _p2p_signature_error("P2P-Anfrage ist zu groß", 413)

        node_id = str(request.headers.get("X-DCloud-Node-Id") or "").strip()
        public_key_b64 = str(request.headers.get("X-DCloud-Public-Key") or "").strip()
        timestamp_text = str(request.headers.get("X-DCloud-Timestamp") or "").strip()
        nonce = str(request.headers.get("X-DCloud-Nonce") or "").strip()
        body_hash = str(request.headers.get("X-DCloud-Body-SHA256") or "").strip().lower()
        signature = str(request.headers.get("X-DCloud-Signature") or "").strip()
        if not all([node_id, public_key_b64, timestamp_text, nonce, body_hash, signature]):
            return _p2p_signature_error("P2P-Signatur fehlt")
        if len(nonce) > 96 or not re.match(r"^[A-Za-z0-9_.:-]+$", nonce):
            return _p2p_signature_error("P2P-Nonce ist ungültig")
        try:
            timestamp = float(timestamp_text)
        except ValueError:
            return _p2p_signature_error("P2P-Zeitstempel ist ungültig")
        now = time.time()
        if abs(now - timestamp) > P2P_SIGNATURE_WINDOW_SECONDS:
            return _p2p_signature_error("P2P-Signatur ist abgelaufen")
        try:
            public_key_bytes = b64decode(public_key_b64)
        except Exception:
            return _p2p_signature_error("P2P-Public-Key ist ungültig")
        if derive_node_id(public_key_bytes) != node_id:
            return _p2p_signature_error("P2P-Node-ID passt nicht zum Public-Key")
        body = request.get_data(cache=True) if request.method.upper() != "GET" else b""
        actual_hash = sha256_hex(body)
        if body_hash != actual_hash:
            return _p2p_signature_error("P2P-Body-Hash passt nicht")
        nonce_key = f"{node_id}:{nonce}"
        with p2p_nonce_lock:
            if nonce_key in p2p_seen_nonces:
                return _p2p_signature_error("P2P-Anfrage wurde bereits verwendet")
            p2p_seen_nonces[nonce_key] = now
        path_with_query = request.full_path[:-1] if request.full_path.endswith("?") else request.full_path
        canonical = "\n".join([
            request.method.upper(),
            path_with_query,
            timestamp_text,
            nonce,
            actual_hash,
        ]).encode("utf-8")
        if not verify_signature(public_key_bytes, canonical, signature):
            return _p2p_signature_error("P2P-Signatur ist ungültig")
        request.environ["dcloud.p2p_node_id"] = node_id
        return None

    def _env_flag(name: str, default: bool = False) -> bool:
        raw = os.environ.get(name)
        if raw is None or str(raw).strip() == "":
            return default
        return str(raw).strip().lower() in {"1", "true", "yes", "on", "enabled", "ja"}

    def _resolve_browser_host_addresses(hostname: str) -> tuple[bool, list[ipaddress._BaseAddress]]:
        host = (hostname or "").strip().strip("[]").lower().rstrip(".")
        if not host:
            return False, []
        try:
            return True, [ipaddress.ip_address(host)]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            raise StorageError("Hostname konnte nicht aufgelöst werden")
        addresses: list[ipaddress._BaseAddress] = []
        for info in infos:
            sockaddr = info[4]
            if not sockaddr:
                continue
            try:
                candidate = ipaddress.ip_address(str(sockaddr[0]).strip("[]"))
            except ValueError:
                continue
            if candidate not in addresses:
                addresses.append(candidate)
        return False, addresses

    def _validate_external_browser_target(url: str) -> None:
        parsed = url_parse.urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise StorageError("Der interne Browser erlaubt nur http:// und https:// URLs.")
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise StorageError("URL enthält keinen Hostnamen")
        if hostname.endswith(".dcloud"):
            return

        host = hostname.strip().strip("[]").lower().rstrip(".")
        if host in {"localhost", "localhost.localdomain", "host.docker.internal"} or host.endswith(".local"):
            raise StorageError("Diese lokale Adresse wurde aus Sicherheitsgründen blockiert. Nutze für dcloud-Peers bitte peername.dcloud oder die direkte LAN-IP.")

        literal_ip, addresses = _resolve_browser_host_addresses(hostname)
        if not addresses:
            raise StorageError("Hostname konnte nicht aufgelöst werden")

        allow_lan_literals = _env_flag("DCLOUD_BROWSER_ALLOW_LAN_IPS", True)
        for address in addresses:
            if address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or address.is_unspecified:
                raise StorageError("Diese Adresse wurde aus Sicherheitsgründen blockiert.")
            if address.is_private:
                # LAN IPs such as 192.168.x.x are useful for managing Windows peers
                # from the dashboard browser.  To keep the SSRF protection meaningful,
                # only literal private IPs are allowed by default; DNS names that resolve
                # into private networks stay blocked unless the administrator explicitly
                # enables DCLOUD_BROWSER_ALLOW_PRIVATE_DNS=1.
                if literal_ip and allow_lan_literals:
                    continue
                if (not literal_ip) and _env_flag("DCLOUD_BROWSER_ALLOW_PRIVATE_DNS", False):
                    continue
                raise StorageError("Diese Adresse wurde aus Sicherheitsgründen blockiert, weil sie auf ein lokales oder privates Netzwerk zeigt. Direkte LAN-IPs können mit DCLOUD_BROWSER_ALLOW_LAN_IPS=1 erlaubt werden.")

        port = parsed.port
        allowed_ports = {80, 443, 8080, 8443, int(config.web.port)}
        if port is not None and port not in allowed_ports:
            raise StorageError("Dieser Port ist im Dashboard-Browser nicht erlaubt.")

    def _is_ajax_request() -> bool:
        return request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.accept_mimetypes.best == "application/json"

    def _safe_upload_id(value: str | None) -> str:
        cleaned = "".join(char for char in (value or "") if char.isalnum() or char in "-_")[:80]
        return cleaned or uuid4().hex

    def _safe_peer_id(value: str | None) -> str:
        return "".join(char for char in (value or "") if char.isalnum() or char in "-_")[:128]

    def _web_host_slug(value: str | None) -> str:
        """Return a DNS-ish label used by the internal .dcloud browser."""
        normalized = unicodedata.normalize("NFKD", str(value or ""))
        ascii_text = normalized.encode("ascii", "ignore").decode("ascii")
        slug = re.sub(r"[^a-z0-9-]+", "-", ascii_text.lower()).strip("-")
        slug = re.sub(r"-+", "-", slug)
        if len(slug) > 48:
            slug = slug[:48].strip("-")
        return slug

    def _web_host_candidates(node_id: str, configured_name: str | None = None) -> list[str]:
        configured = str(configured_name or "").strip()
        configured_slug = "" if configured.lower() in {"", "dcloud-node", "node", "client", "server"} else _web_host_slug(configured)
        candidates = [
            configured_slug,
            _web_host_slug(display_name_for_peer(node_id, configured_name)),
            _web_host_slug(node_id[:12]),
        ]
        result: list[str] = []
        for candidate in candidates:
            if candidate and candidate not in result:
                result.append(candidate)
        return result or ["peer"]

    def _primary_web_hostname() -> str:
        return f"{_web_host_candidates(identity.node_id, config.node.name)[0]}.dcloud"

    def _php_binary() -> str:
        return shutil.which("php-cgi") or shutil.which("php") or ""

    def _default_web_index_html() -> str:
        host = html.escape(_primary_web_hostname())
        display_name = html.escape(display_name_for_peer(identity.node_id, config.node.name))
        return f"""<!doctype html>
<html lang=\"de\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{display_name} · dcloud Web</title>
  <style>
    body{{margin:0;font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:linear-gradient(135deg,#07111f,#0d63d8);color:white;min-height:100vh;display:grid;place-items:center}}
    main{{width:min(860px,calc(100vw - 32px));padding:42px;border:1px solid rgba(255,255,255,.28);border-radius:28px;background:rgba(255,255,255,.13);box-shadow:0 24px 80px rgba(0,0,0,.35);backdrop-filter:blur(18px)}}
    h1{{font-size:clamp(2rem,6vw,4.5rem);margin:0 0 10px}}
    p{{font-size:1.1rem;line-height:1.65;color:rgba(255,255,255,.88)}}
    code{{background:rgba(0,0,0,.22);padding:.16rem .38rem;border-radius:.42rem}}
  </style>
</head>
<body>
  <main>
    <h1>Willkommen auf {host}</h1>
    <p>Diese Seite wird direkt aus dem lokalen dcloud-Ordner <code>storage/web</code> ausgeliefert.</p>
    <p>Lege hier eigene <code>.html</code>, Assets und optional <code>.php</code>-Dateien ab. Im internen Browser ist die Seite unter <code>http://{host}</code> erreichbar.</p>
  </main>
</body>
</html>
"""

    def _ensure_web_root() -> None:
        web_root.mkdir(parents=True, exist_ok=True)
        index_path = web_root / "index.html"
        if not index_path.exists():
            index_path.write_text(_default_web_index_html(), encoding="utf-8")
        readme_path = web_root / "README.txt"
        if not readme_path.exists():
            readme_path.write_text(
                "dcloud Web-Ordner\n\n"
                "Dateien in diesem Ordner werden vom lokalen dcloud-Node ausgeliefert.\n"
                f"Startseite im internen Browser: http://{_primary_web_hostname()}/\n\n"
                "Dieser Ordner erscheint im dcloud Datei-Explorer als Spezialordner 'web'.\n"
                "Dort kannst du HTML-, PHP-, CSS-, JavaScript- und Asset-Dateien hochladen,\n"
                "Unterordner anlegen und bearbeitbare Textdateien im integrierten Web-Texteditor speichern.\n\n"
                "Unterstuetzt werden statische HTML/CSS/JS-Dateien und PHP-Dateien, "
                "wenn php-cgi oder php auf dem System installiert ist. PHP ist eine System-Abhaengigkeit "
                "und kann nicht per pip requirements.txt installiert werden.\n",
                encoding="utf-8",
            )

    def _safe_web_path(raw_path: str | None) -> Path:
        clean = str(raw_path or "").split("?", 1)[0].replace("\\", "/").lstrip("/")
        if not clean or clean.endswith("/"):
            clean = f"{clean}index.html"
        candidate = (web_root / clean).resolve()
        root = web_root.resolve()
        if candidate != root and root not in candidate.parents:
            raise StorageError("Web-Pfad ist ungültig")
        if candidate.is_dir():
            candidate = candidate / "index.html"
        return candidate

    def _split_cgi_response(raw: bytes) -> tuple[dict[str, str], bytes]:
        for separator in (b"\r\n\r\n", b"\n\n"):
            if separator in raw:
                header_blob, body = raw.split(separator, 1)
                headers: dict[str, str] = {}
                for line in header_blob.replace(b"\r\n", b"\n").split(b"\n"):
                    if b":" not in line:
                        continue
                    key, value = line.split(b":", 1)
                    headers[key.decode("latin1", errors="ignore").strip()] = value.decode("latin1", errors="ignore").strip()
                return headers, body
        return {}, raw

    def _render_php_file(script_path: Path, web_path: str, *, query_string: str | None = None) -> Response:
        php_binary = _php_binary()
        if not php_binary:
            return Response(
                "PHP-Unterstützung ist nicht aktiv: Installiere php-cgi oder php auf diesem System.",
                status=501,
                content_type="text/plain; charset=utf-8",
            )
        body = request.get_data() if request.method in {"POST", "PUT", "PATCH"} else b""
        env = os.environ.copy()
        env.update(
            {
                "GATEWAY_INTERFACE": "CGI/1.1",
                "SERVER_PROTOCOL": "HTTP/1.1",
                "REQUEST_METHOD": request.method,
                "QUERY_STRING": request.query_string.decode("latin1", errors="ignore") if query_string is None else str(query_string),
                "SCRIPT_FILENAME": str(script_path),
                "SCRIPT_NAME": "/dcloud-site/" + web_path.lstrip("/"),
                "DOCUMENT_ROOT": str(web_root.resolve()),
                "SERVER_NAME": _primary_web_hostname(),
                "SERVER_PORT": str(config.web.port),
                "CONTENT_TYPE": request.headers.get("Content-Type", ""),
                "CONTENT_LENGTH": str(len(body)),
                "REDIRECT_STATUS": "200",
            }
        )
        command = [php_binary]
        if Path(php_binary).name != "php-cgi":
            command = [php_binary, str(script_path)]
        try:
            result = subprocess.run(
                command,
                input=body,
                capture_output=True,
                env=env,
                cwd=str(script_path.parent),
                timeout=20,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return Response("PHP-Skript hat das Zeitlimit überschritten.", status=504, content_type="text/plain; charset=utf-8")
        except Exception as exc:
            return Response(f"PHP-Ausführung fehlgeschlagen: {exc}", status=500, content_type="text/plain; charset=utf-8")
        if result.returncode != 0:
            message = result.stderr.decode("utf-8", errors="replace") or "PHP-Skript wurde mit Fehler beendet."
            return Response(message, status=500, content_type="text/plain; charset=utf-8")
        headers, response_body = _split_cgi_response(result.stdout)
        status = 200
        status_header = headers.pop("Status", "")
        if status_header:
            try:
                status = int(status_header.split()[0])
            except Exception:
                status = 200
        response_headers = {}
        for key, value in headers.items():
            if key.lower() in {"content-type", "location", "cache-control"}:
                response_headers[key] = value
        if not any(key.lower() == "content-type" for key in response_headers):
            response_headers["Content-Type"] = "text/html; charset=utf-8"
        return Response(response_body, status=status, headers=response_headers)

    def _serve_local_web_path(path: str | None = None, *, query_string: str | None = None) -> Response:
        try:
            _ensure_web_root()
            file_path = _safe_web_path(path)
        except StorageError as exc:
            return Response(str(exc), status=400, content_type="text/plain; charset=utf-8")
        except Exception as exc:
            return Response(
                f"dcloud Webspace konnte nicht vorbereitet werden: {type(exc).__name__}: {exc}",
                status=500,
                content_type="text/plain; charset=utf-8",
            )
        if not file_path.exists() or not file_path.is_file():
            return Response("Web-Datei nicht gefunden", status=404, content_type="text/plain; charset=utf-8")
        try:
            rel_path = file_path.relative_to(web_root.resolve()).as_posix()
            if file_path.suffix.lower() == ".php":
                return _render_php_file(file_path, rel_path, query_string=query_string)
            return send_file(file_path, conditional=True)
        except Exception as exc:
            return Response(
                f"dcloud Webspace-Datei konnte nicht ausgeliefert werden: {type(exc).__name__}: {exc}",
                status=500,
                content_type="text/plain; charset=utf-8",
            )

    def _normalize_web_relative(raw_path: str | None, *, allow_empty: bool = False) -> str:
        clean = url_parse.unquote(str(raw_path or "")).split("?", 1)[0].replace("\\", "/").strip("/")
        if clean == WEB_EXPLORER_FOLDER:
            clean = ""
        elif clean.startswith(f"{WEB_EXPLORER_FOLDER}/"):
            clean = clean[len(WEB_EXPLORER_FOLDER) + 1:]
        parts = []
        for part in clean.split("/"):
            part = part.strip()
            if not part or part in {".", ".."}:
                continue
            if "\0" in part:
                raise StorageError("Web-Pfad ist ungültig")
            parts.append(part)
        relative = "/".join(parts)
        if not relative and not allow_empty:
            raise StorageError("Web-Pfad fehlt")
        return relative

    def _safe_web_file_path(raw_path: str | None, *, allow_directory: bool = False, allow_empty: bool = False) -> Path:
        relative = _normalize_web_relative(raw_path, allow_empty=allow_empty)
        candidate = (web_root / relative).resolve()
        root = web_root.resolve()
        if candidate != root and root not in candidate.parents:
            raise StorageError("Web-Pfad ist ungültig")
        if not allow_directory and candidate.exists() and candidate.is_dir():
            raise StorageError("Der angegebene Web-Pfad ist ein Ordner")
        return candidate

    def _is_web_text_editable(path: Path) -> bool:
        return path.suffix.lower() in WEB_EDITABLE_SUFFIXES or path.name.lower() in {"readme", "license", "htaccess", ".htaccess"}

    def web_files_payload() -> dict[str, Any]:
        _ensure_web_root()
        root = web_root.resolve()
        folders: list[str] = []
        files: list[dict[str, Any]] = []
        for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().lower()):
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                continue
            if path.is_dir():
                folders.append(rel)
                continue
            if not path.is_file():
                continue
            stat = path.stat()
            parent = path.parent.relative_to(root).as_posix() if path.parent != root else ""
            files.append({
                "path": rel,
                "name": path.name,
                "folder": parent,
                "size": stat.st_size,
                "modifiedAt": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "editable": _is_web_text_editable(path) and stat.st_size <= WEB_EDIT_MAX_BYTES,
                "tooLargeToEdit": _is_web_text_editable(path) and stat.st_size > WEB_EDIT_MAX_BYTES,
                "mimeType": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
                "siteUrl": "/dcloud-site/" + url_parse.quote(rel),
                "readUrl": url_for("api_web_file") + "?path=" + url_parse.quote(rel),
                "deleteUrl": url_for("api_web_delete"),
            })
        return {
            "rootFolder": WEB_EXPLORER_FOLDER,
            "rootPath": str(root),
            "folders": folders,
            "files": files,
            "editMaxBytes": WEB_EDIT_MAX_BYTES,
        }

    def _web_json_state(message: str, *, ok: bool = True, status: int = 200) -> tuple[Response, int] | Response:
        payload = {"ok": ok, "message": message, "webFiles": web_files_payload(), "state": state_payload()}
        response = jsonify(payload)
        return (response, status) if status != 200 else response

    def _ensure_browser_downloads_root() -> None:
        browser_downloads_root.mkdir(parents=True, exist_ok=True)

    def _normalize_browser_download_relative(raw_path: str | None, *, allow_empty: bool = False) -> str:
        clean = url_parse.unquote(str(raw_path or "")).split("?", 1)[0].replace("\\", "/").strip("/")
        if clean == BROWSER_DOWNLOADS_FOLDER:
            clean = ""
        elif clean.startswith(f"{BROWSER_DOWNLOADS_FOLDER}/"):
            clean = clean[len(BROWSER_DOWNLOADS_FOLDER) + 1:]
        parts = []
        for part in clean.split("/"):
            part = part.strip()
            if not part or part in {".", ".."}:
                continue
            if "\0" in part:
                raise StorageError("Download-Pfad ist ungültig")
            parts.append(part)
        relative = "/".join(parts)
        if not relative and not allow_empty:
            raise StorageError("Download-Pfad fehlt")
        return relative

    def _safe_browser_download_path(raw_path: str | None, *, allow_directory: bool = False, allow_empty: bool = False) -> Path:
        relative = _normalize_browser_download_relative(raw_path, allow_empty=allow_empty)
        candidate = (browser_downloads_root / relative).resolve()
        root = browser_downloads_root.resolve()
        if candidate != root and root not in candidate.parents:
            raise StorageError("Download-Pfad ist ungültig")
        if not allow_directory and candidate.exists() and candidate.is_dir():
            raise StorageError("Der angegebene Download-Pfad ist ein Ordner")
        return candidate

    def _is_internal_browser_download_artifact(path: Path, root: Path) -> bool:
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            return True
        if any(part.startswith(".") for part in rel_parts):
            return True
        name = path.name.strip()
        if name.endswith(('.tmp', '.part', '.crdownload')):
            return True
        if BROWSER_DOWNLOAD_INTERNAL_ARTIFACT_RE.match(name):
            return True
        return False

    def browser_downloads_payload() -> dict[str, Any]:
        _ensure_browser_downloads_root()
        root = browser_downloads_root.resolve()
        folders: list[str] = []
        files: list[dict[str, Any]] = []
        visible_folders: set[str] = set()
        for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().lower()):
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                continue
            if _is_internal_browser_download_artifact(path, root):
                continue
            if path.is_dir():
                folders.append(rel)
                continue
            if not path.is_file():
                continue
            parent = path.parent.relative_to(root).as_posix() if path.parent != root else ""
            if parent:
                visible_folders.add(parent)
            stat = path.stat()
            quoted = url_parse.quote(rel)
            files.append({
                "path": rel,
                "name": path.name,
                "folder": parent,
                "size": stat.st_size,
                "modifiedAt": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "mimeType": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
                "downloadUrl": url_for("api_browser_download_file") + "?path=" + quoted,
                "previewUrl": url_for("api_browser_download_file") + "?inline=1&path=" + quoted,
                "deleteUrl": url_for("api_browser_download_delete"),
            })
        for folder in list(visible_folders):
            parts = Path(folder).parts
            for index in range(1, len(parts) + 1):
                visible_folders.add("/".join(parts[:index]))
        visible_folder_set = set(folders) | visible_folders
        return {
            "rootFolder": BROWSER_DOWNLOADS_FOLDER,
            "rootPath": str(root),
            "folders": sorted(visible_folder_set),
            "files": files,
        }

    def _browser_download_json_state(message: str, *, ok: bool = True, status: int = 200) -> tuple[Response, int] | Response:
        payload = {"ok": ok, "message": message, "browserDownloads": browser_downloads_payload(), "state": state_payload()}
        response = jsonify(payload)
        return (response, status) if status != 200 else response

    def _safe_search_url(query: str) -> str:
        cleaned = str(query or "").strip()
        return "https://duckduckgo.com/html/?q=" + url_parse.quote_plus(cleaned)

    def _browser_url(value: str | None) -> str:
        raw = str(value or "").strip()
        if not raw:
            return f"http://{_primary_web_hostname()}/"
        if raw.lower().startswith(("g:", "google:")):
            return _safe_search_url(raw.split(":", 1)[1])
        if raw.startswith("//"):
            return "https:" + raw
        if "://" not in raw:
            # Plain text with spaces is treated as a search query. This keeps the
            # server-side dashboard browser usable without depending on Google,
            # whose reCAPTCHA/site-key checks intentionally reject proxied origins.
            if any(ch.isspace() for ch in raw):
                return _safe_search_url(raw)
            raw = ("http://" if raw.lower().endswith(".dcloud") or ".dcloud/" in raw.lower() else "https://") + raw
        return raw

    def _is_google_host(hostname: str) -> bool:
        host = (hostname or "").lower().strip(".")
        return host == "google.com" or host.endswith(".google.com") or host.startswith("google.") or ".google." in host

    def _browser_proxy_url_for(target_url: str, *, native_mode: bool = False) -> str:
        proxied = url_for("browser_view") + "?url=" + url_parse.quote(target_url, safe="")
        if native_mode:
            proxied += "&native=1"
        token = str(request.args.get("browser_token") or "")
        if token and secrets.compare_digest(token, browser_access_token):
            proxied += "&browser_token=" + url_parse.quote(token, safe="")
        return proxied

    def _google_proxy_notice_response(original_url: str, *, query: str = "", details: str = "") -> Response:
        q = html.escape(query or "", quote=True)
        target = html.escape(original_url or "https://www.google.com/", quote=True)
        ddg_url = _safe_search_url(query) if query else "https://duckduckgo.com/html/"
        ddg_proxy = html.escape(_browser_proxy_url_for(ddg_url), quote=True)
        details_html = f"<p class='muted'>{html.escape(details)}</p>" if details else ""
        body = f"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Google im dcloud-Proxy</title>
<style>
  body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#eef4ff;color:#162033;font-family:system-ui,-apple-system,Segoe UI,sans-serif}}
  main{{max-width:760px;margin:24px;background:#fff;border:1px solid #d9e5f5;border-radius:24px;padding:30px;box-shadow:0 20px 60px rgba(20,40,80,.14)}}
  h1{{margin:0 0 12px;font-size:1.55rem}}
  p{{line-height:1.55}}
  code{{background:#edf2ff;border-radius:7px;padding:.13rem .35rem}}
  form{{display:flex;gap:10px;margin:20px 0 12px;flex-wrap:wrap}}
  input{{flex:1;min-width:260px;border:1px solid #b8c7df;border-radius:13px;padding:.75rem .9rem;font-size:1rem}}
  button,a.button{{border:0;border-radius:13px;background:#0b63ce;color:#fff;font-weight:800;padding:.78rem 1rem;text-decoration:none;display:inline-flex;align-items:center}}
  .muted{{color:#5d6f87;font-size:.94rem}}
  .actions{{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}}
</style>
</head>
<body><main>
<h1>Google blockiert die Proxy-Ansicht</h1>
<p>Google/reCAPTCHA erlaubt seine Sicherheitsprüfung nur auf freigegebenen Google-Domains. Im dcloud-Dashboard läuft die Seite aber technisch über deinen dcloud-Server, zum Beispiel <code>localhost</code> oder deine eigene Dashboard-Domain. Deshalb erscheint die Meldung, dass die Domain für den Websiteschlüssel nicht unterstützt wird.</p>
{details_html}
<form method="get" action="/browser/search">
  <input type="search" name="q" value="{q}" placeholder="Suchbegriff eingeben" autofocus>
  <button type="submit">Mit Proxy-Suche suchen</button>
</form>
<div class="actions">
  <a class="button" href="{ddg_proxy}">Proxy-Suche öffnen</a>
</div>
<p class="muted">Angefragte Adresse: <code>{target}</code></p>
<p class="muted">dcloud umgeht keine CAPTCHA- oder Bot-Schutzmechanismen. Für echte Google-Suche muss Google außerhalb des Server-Proxys im normalen Browser geöffnet werden.</p>
</main></body></html>"""
        response = Response(body, status=200, content_type="text/html; charset=utf-8")
        response.headers["Cache-Control"] = "no-store"
        return response

    def _is_google_captcha_body(body: bytes) -> bool:
        snippet = body[:512000].decode("utf-8", errors="ignore").lower()
        needles = (
            "localhost befindet sich nicht in der liste der unterstützten domains",
            "not in the list of supported domains",
            "invalid domain for site key",
            "unusual traffic from your computer network",
            "sorry/index",
            "g-recaptcha",
            "www.google.com/recaptcha",
        )
        return any(needle in snippet for needle in needles)

    def _resolve_dcloud_peer(hostname: str) -> tuple[str, Any | None]:
        label = hostname.lower().removesuffix(".dcloud").strip(".")
        local_candidates = _web_host_candidates(identity.node_id, config.node.name)
        if label in local_candidates:
            return "local", None
        for peer in _list_active_peers():
            if label in _web_host_candidates(peer.node_id, getattr(peer, "name", None)):
                return "peer", peer
        if label == identity.node_id[:12].lower():
            return "local", None
        for peer in _list_active_peers():
            if label == str(peer.node_id or "")[:12].lower():
                return "peer", peer
        raise StorageError(f"Kein aktiver dcloud-Peer für {hostname} gefunden")

    def _browser_skip_rewrite(target: str) -> bool:
        value = (target or "").strip()
        if not value:
            return True
        lower = value.lower()
        return lower.startswith(("#", "mailto:", "tel:", "javascript:", "data:", "blob:", "about:"))

    def _browser_proxy_target(target: str, base_url: str, *, native_mode: bool = False) -> str:
        if _browser_skip_rewrite(target):
            return target
        absolute = url_parse.urljoin(base_url, html.unescape(target.strip()))
        parsed = url_parse.urlsplit(absolute)
        host = (parsed.hostname or "").lower()
        if parsed.scheme.lower() not in {"http", "https"}:
            return target
        if native_mode and not host.endswith(".dcloud"):
            return absolute
        return _browser_proxy_url_for(absolute, native_mode=native_mode)

    def _rewrite_browser_css(text: str, base_url: str, *, native_mode: bool = False) -> str:
        def url_repl(match: re.Match[str]) -> str:
            quote = match.group(1) or ""
            target = match.group(2).strip()
            if _browser_skip_rewrite(target):
                return match.group(0)
            proxied = _browser_proxy_target(target, base_url, native_mode=native_mode)
            return f"url({quote}{proxied}{quote})"

        text = re.sub(r"url\(\s*(['\"]?)([^)'\"]+)\1\s*\)", url_repl, text, flags=re.IGNORECASE)

        def import_repl(match: re.Match[str]) -> str:
            quote = match.group(1)
            target = match.group(2).strip()
            proxied = _browser_proxy_target(target, base_url, native_mode=native_mode)
            return f"@import {quote}{proxied}{quote}"

        return re.sub(r"@import\s+(['\"])(.*?)\1", import_repl, text, flags=re.IGNORECASE)

    def _rewrite_browser_js(text: str, base_url: str, *, native_mode: bool = False) -> str:
        """Conservatively rewrite JavaScript module/worker/import URLs for the dashboard proxy."""

        def likely_url_literal(target: str) -> bool:
            value = html.unescape((target or "").strip())
            if _browser_skip_rewrite(value):
                return False
            lower = value.lower()
            return (
                lower.startswith(("http://", "https://", "//", "/", "./", "../"))
                or lower.endswith(".dcloud")
                or ".dcloud/" in lower
            )

        def quoted_repl(match: re.Match[str]) -> str:
            prefix = match.group(1)
            quote = match.group(2)
            target = match.group(3)
            suffix = match.group(4) if match.lastindex and match.lastindex >= 4 else ""
            if not likely_url_literal(target):
                return match.group(0)
            proxied = _browser_proxy_target(target, base_url, native_mode=native_mode)
            return f"{prefix}{quote}{proxied}{suffix}"

        text = re.sub(
            r"(\b(?:import|export)\s+(?:[^'\"]*?\s+from\s+)?)(['\"])([^'\"]+)(\2)",
            lambda m: quoted_repl(m),
            text,
        )
        text = re.sub(
            r"(\b(?:import|importScripts|Worker|SharedWorker)\s*\(\s*)(['\"])([^'\"]+)(\2)",
            lambda m: quoted_repl(m),
            text,
        )
        text = re.sub(
            r"(\bserviceWorker\.register\s*\(\s*)(['\"])([^'\"]+)(\2)",
            lambda m: quoted_repl(m),
            text,
        )
        return text

    def _rewrite_browser_srcset(value: str, base_url: str, *, native_mode: bool = False) -> str:
        parts: list[str] = []
        for raw_candidate in value.split(","):
            candidate = raw_candidate.strip()
            if not candidate:
                continue
            bits = candidate.split(None, 1)
            target = bits[0]
            descriptor = (" " + bits[1]) if len(bits) > 1 else ""
            parts.append(_browser_proxy_target(target, base_url, native_mode=native_mode) + descriptor)
        return ", ".join(parts) if parts else value

    def _browser_injection_script(base_url: str, *, native_mode: bool = False) -> str:
        base_json = json.dumps(base_url)
        native_json = "true" if native_mode else "false"
        token = str(request.args.get("browser_token") or "")
        token_part = "&browser_token=" + url_parse.quote(token, safe="") if token and secrets.compare_digest(token, browser_access_token) else ""
        token_json = json.dumps(token_part)
        return f'''
<script data-dcloud-browser-proxy="1">
(() => {{
  if(window.__dcloudBrowserProxyInstalled) return;
  window.__dcloudBrowserProxyInstalled = true;
  const DCLOUD_BASE_URL = {base_json};
  const DCLOUD_NATIVE_MODE = {native_json};
  const DCLOUD_TOKEN_PART = {token_json};
  const PROXY_PATH = '/browser/view';
  const URL_ATTRS = new Set(['href','src','action','formaction','poster','data-src','data-href']);
  const skip = value => /^(#|mailto:|tel:|javascript:|data:|blob:|about:)/i.test(String(value || '').trim());
  const isProxyUrl = value => {{
    try {{
      const parsed = new URL(String(value || ''), window.location.href);
      return parsed.origin === window.location.origin && parsed.pathname === PROXY_PATH && parsed.searchParams.has('url');
    }} catch(error) {{ return false; }}
  }};
  const absoluteUrl = (value, base = DCLOUD_BASE_URL) => new URL(String(value || ''), base).href;
  const proxify = (value, base = DCLOUD_BASE_URL) => {{
    try {{
      if(skip(value) || isProxyUrl(value)) return value;
      const absolute = absoluteUrl(value, base);
      const parsed = new URL(absolute);
      if(!/^https?:$/i.test(parsed.protocol)) return value;
      if(DCLOUD_NATIVE_MODE && !parsed.hostname.toLowerCase().endsWith('.dcloud')) return absolute;
      return PROXY_PATH + '?url=' + encodeURIComponent(absolute) + (DCLOUD_NATIVE_MODE ? '&native=1' : '') + DCLOUD_TOKEN_PART;
    }} catch(error) {{ return value; }}
  }};
  const remoteFromProxy = value => {{
    try {{
      const parsed = new URL(String(value || ''), window.location.href);
      if(parsed.origin === window.location.origin && parsed.pathname === PROXY_PATH && parsed.searchParams.has('url')) return parsed.searchParams.get('url') || DCLOUD_BASE_URL;
    }} catch(error) {{}}
    return value || DCLOUD_BASE_URL;
  }};
  const notifyParentUrl = (url, loading = true) => {{
    try {{
      const remote = remoteFromProxy(url || DCLOUD_BASE_URL);
      if(window.parent && window.parent !== window) window.parent.postMessage({{type:'dcloud-browser-url-changed', url: remote, loading: !!loading}}, '*');
    }} catch(error) {{}}
  }};
  const navigateViaProxy = value => {{
    const remote = remoteFromProxy(value || DCLOUD_BASE_URL);
    notifyParentUrl(remote, true);
    window.location.href = proxify(remote);
  }};
  const proxifySrcset = value => String(value || '').split(',').map(candidate => {{
    const trimmed = candidate.trim();
    if(!trimmed) return trimmed;
    const parts = trimmed.split(/\\s+/, 2);
    const rest = trimmed.slice(parts[0].length);
    return proxify(parts[0]) + rest;
  }}).join(', ');
  const rewriteElement = element => {{
    if(!element || element.nodeType !== 1 || element.dataset?.dcloudRewritten === '1') return;
    try {{
      for(const attr of URL_ATTRS) {{
        if(element.hasAttribute?.(attr)) element.setAttribute(attr, proxify(element.getAttribute(attr)));
      }}
      if(element.hasAttribute?.('srcset')) element.setAttribute('srcset', proxifySrcset(element.getAttribute('srcset')));
      if((element.tagName === 'A' || element.tagName === 'FORM') && element.hasAttribute?.('target')) element.removeAttribute('target');
      if(element.dataset) element.dataset.dcloudRewritten = '1';
    }} catch(error) {{}}
  }};
  const rewriteAll = root => {{
    try {{ (root || document).querySelectorAll?.('[href],[src],[action],[formaction],[poster],[srcset],[data-src],[data-href]').forEach(rewriteElement); }} catch(error) {{}}
  }};
  const submitFormThroughProxy = form => {{
    try {{
      const method = String(form.getAttribute('method') || form.method || 'GET').toUpperCase();
      const rawAction = form.getAttribute('action') || window.location.href || DCLOUD_BASE_URL;
      const remoteAction = remoteFromProxy(rawAction);
      if(method === 'GET') {{
        const target = new URL(remoteAction || DCLOUD_BASE_URL, DCLOUD_BASE_URL);
        const data = new FormData(form);
        for(const [key, value] of data.entries()) target.searchParams.append(key, value);
        navigateViaProxy(target.href);
        return true;
      }}
      form.setAttribute('action', proxify(remoteAction));
    }} catch(error) {{}}
    return false;
  }};
  try {{
    const originalSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {{
      try {{
        const lower = String(name || '').toLowerCase();
        if(URL_ATTRS.has(lower)) value = proxify(value);
        else if(lower === 'srcset') value = proxifySrcset(value);
      }} catch(error) {{}}
      return originalSetAttribute.call(this, name, value);
    }};
  }} catch(error) {{}}
  const patchUrlProperty = (proto, prop) => {{
    try {{
      const descriptor = Object.getOwnPropertyDescriptor(proto, prop);
      if(!descriptor || !descriptor.set || !descriptor.get) return;
      Object.defineProperty(proto, prop, {{
        configurable: true,
        enumerable: descriptor.enumerable,
        get() {{ return descriptor.get.call(this); }},
        set(value) {{ return descriptor.set.call(this, proxify(value)); }}
      }});
    }} catch(error) {{}}
  }};
  patchUrlProperty(HTMLAnchorElement.prototype, 'href');
  patchUrlProperty(HTMLLinkElement.prototype, 'href');
  patchUrlProperty(HTMLImageElement.prototype, 'src');
  patchUrlProperty(HTMLScriptElement.prototype, 'src');
  patchUrlProperty(HTMLFormElement.prototype, 'action');
  if(window.HTMLIFrameElement) patchUrlProperty(HTMLIFrameElement.prototype, 'src');
  if(window.HTMLSourceElement) patchUrlProperty(HTMLSourceElement.prototype, 'src');
  rewriteAll(document);
  document.addEventListener('click', event => {{
    const link = event.target && event.target.closest ? event.target.closest('a[href]') : null;
    if(!link) return;
    const href = link.getAttribute('href');
    if(skip(href)) return;
    event.preventDefault();
    event.stopPropagation();
    navigateViaProxy(href);
  }}, true);
  document.addEventListener('submit', event => {{
    const form = event.target;
    if(form && form.getAttribute && submitFormThroughProxy(form)) {{
      event.preventDefault();
      event.stopPropagation();
    }}
  }}, true);
  try {{
    const originalSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function() {{ if(submitFormThroughProxy(this)) return; return originalSubmit.call(this); }};
    const originalRequestSubmit = HTMLFormElement.prototype.requestSubmit;
    if(originalRequestSubmit) HTMLFormElement.prototype.requestSubmit = function(submitter) {{ if(submitFormThroughProxy(this)) return; return originalRequestSubmit.call(this, submitter); }};
  }} catch(error) {{}}
  const originalOpenWindow = window.open;
  if(originalOpenWindow) window.open = function(url, name, features) {{
    const remote = remoteFromProxy(url || DCLOUD_BASE_URL);
    notifyParentUrl(remote, true);
    return originalOpenWindow.call(window, proxify(remote), name || '_self', features);
  }};
  const originalFetch = window.fetch;
  if(originalFetch) window.fetch = function(input, init) {{
    try {{
      if(typeof input === 'string' || input instanceof URL) input = proxify(input.toString());
      else if(input && input.url) input = new Request(proxify(input.url), input);
    }} catch(error) {{}}
    return originalFetch.call(this, input, init);
  }};
  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {{
    try {{ arguments[1] = proxify(url); }} catch(error) {{}}
    return originalOpen.apply(this, arguments);
  }};
  try {{
    const originalAssign = window.location.assign.bind(window.location);
    const originalReplace = window.location.replace.bind(window.location);
    window.location.assign = value => {{ const remote = remoteFromProxy(value); notifyParentUrl(remote, true); return originalAssign(proxify(remote)); }};
    window.location.replace = value => {{ const remote = remoteFromProxy(value); notifyParentUrl(remote, true); return originalReplace(proxify(remote)); }};
  }} catch(error) {{}}
  const observer = new MutationObserver(mutations => mutations.forEach(m => m.addedNodes && m.addedNodes.forEach(node => {{
    if(node.nodeType === 1) {{ rewriteElement(node); rewriteAll(node); }}
  }})));
  try {{ observer.observe(document.documentElement, {{ childList:true, subtree:true }}); }} catch(error) {{}}
  notifyParentUrl(DCLOUD_BASE_URL, false);
  setTimeout(() => rewriteAll(document), 80);
  setInterval(() => rewriteAll(document), 1500);
}})();
</script>
'''

    def _rewrite_browser_html(body: bytes, base_url: str, *, native_mode: bool = False) -> bytes:
        text = body.decode("utf-8", errors="replace")
        text = re.sub(r"<meta[^>]+http-equiv\s*=\s*(['\"]?)Content-Security-Policy\1[^>]*>", "", text, flags=re.IGNORECASE | re.DOTALL)
        attr_names = "href|src|action|formaction|poster|data-src|data-href"

        def repl(match: re.Match[str]) -> str:
            attr = match.group(1)
            quote = match.group(2)
            target = html.unescape(match.group(3).strip())
            if _browser_skip_rewrite(target):
                return match.group(0)
            proxied = _browser_proxy_target(target, base_url, native_mode=native_mode)
            return f'{attr}={quote}{html.escape(proxied, quote=True)}{quote}'

        text = re.sub(rf"\b({attr_names})\s*=\s*([\"'])(.*?)\2", repl, text, flags=re.IGNORECASE | re.DOTALL)

        def srcset_repl(match: re.Match[str]) -> str:
            attr = match.group(1)
            quote = match.group(2)
            value = html.unescape(match.group(3).strip())
            rewritten = _rewrite_browser_srcset(value, base_url, native_mode=native_mode)
            return f'{attr}={quote}{html.escape(rewritten, quote=True)}{quote}'

        text = re.sub(r"\b(srcset)\s*=\s*([\"'])(.*?)\2", srcset_repl, text, flags=re.IGNORECASE | re.DOTALL)

        def style_repl(match: re.Match[str]) -> str:
            return match.group(1) + _rewrite_browser_css(match.group(2), base_url, native_mode=native_mode) + match.group(3)

        text = re.sub(r"(<style[^>]*>)(.*?)(</style>)", style_repl, text, flags=re.IGNORECASE | re.DOTALL)
        injection = _browser_injection_script(base_url, native_mode=native_mode)
        # Important: use a callable replacement here. The injected JavaScript contains
        # backslash sequences such as /\s+/; passing it as a plain replacement string
        # makes re.sub treat them as replacement escapes and raises "bad escape \s".
        if re.search(r"</head\s*>", text, flags=re.IGNORECASE):
            text = re.sub(r"</head\s*>", lambda _match: injection + "</head>", text, count=1, flags=re.IGNORECASE)
        elif re.search(r"</body\s*>", text, flags=re.IGNORECASE):
            text = re.sub(r"</body\s*>", lambda _match: injection + "</body>", text, count=1, flags=re.IGNORECASE)
        else:
            text += injection
        return text.encode("utf-8")

    def _browser_header_value(headers: dict[str, str], name: str) -> str:
        wanted = name.lower()
        for key, value in (headers or {}).items():
            if str(key).lower() == wanted:
                return str(value)
        return ""

    def _browser_request_is_navigation() -> bool:
        dest = request.headers.get("Sec-Fetch-Dest", "").lower()
        mode = request.headers.get("Sec-Fetch-Mode", "").lower()
        accept = request.headers.get("Accept", "").lower()
        return dest in {"", "document", "iframe", "empty"} or mode == "navigate" or "text/html" in accept

    def _browser_download_filename(headers: dict[str, str], final_url: str) -> str:
        disposition = _browser_header_value(headers, "Content-Disposition")
        filename = ""
        star_match = re.search(r"filename\*\s*=\s*(?:UTF-8''|utf-8'')?([^;]+)", disposition, flags=re.IGNORECASE)
        if star_match:
            filename = url_parse.unquote(star_match.group(1).strip().strip('"'))
        if not filename:
            plain_match = re.search(r'filename\s*=\s*(?:"([^"]+)"|([^;]+))', disposition, flags=re.IGNORECASE)
            if plain_match:
                filename = (plain_match.group(1) or plain_match.group(2) or "").strip().strip('"')
        if not filename:
            parsed = url_parse.urlsplit(final_url)
            filename = Path(url_parse.unquote(parsed.path)).name
        return secure_filename(filename) or f"download-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.bin"

    def _browser_response_should_save_download(headers: dict[str, str], final_url: str) -> bool:
        if str(request.args.get("browser_download") or "").lower() in {"1", "true", "yes"}:
            return True
        disposition = _browser_header_value(headers, "Content-Disposition").lower()
        if "attachment" in disposition:
            return True
        if not _browser_request_is_navigation():
            return False
        content_type = _browser_header_value(headers, "Content-Type").split(";", 1)[0].strip().lower()
        inline_types = {
            "text/html", "text/plain", "text/css", "text/javascript", "application/javascript",
            "application/json", "application/xml", "image/svg+xml", "application/xhtml+xml",
        }
        if content_type in inline_types or content_type.startswith("text/") or content_type.startswith("image/") or content_type.startswith("audio/") or content_type.startswith("video/") or content_type.startswith("font/"):
            return False
        extension = Path(url_parse.unquote(url_parse.urlsplit(final_url).path)).suffix.lower()
        if extension in BROWSER_DOWNLOAD_CONTENT_EXTENSIONS:
            return True
        return content_type in {"application/octet-stream", "application/x-msdownload", "application/x-zip-compressed"}

    def _unique_browser_download_path(file_name: str) -> Path:
        _ensure_browser_downloads_root()
        safe_name = secure_filename(file_name) or "download.bin"
        target = browser_downloads_root / safe_name
        if not target.exists():
            return target
        stem = Path(safe_name).stem or "download"
        suffix = Path(safe_name).suffix
        for index in range(2, 10000):
            candidate = browser_downloads_root / f"{stem}-{index}{suffix}"
            if not candidate.exists():
                return candidate
        return browser_downloads_root / f"{stem}-{uuid4().hex[:8]}{suffix}"

    def _save_browser_download_stream(stream: Any, headers: dict[str, str], final_url: str) -> Path:
        output = _unique_browser_download_path(_browser_download_filename(headers, final_url))
        tmp = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
        total = 0
        try:
            with tmp.open("wb") as handle:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    handle.write(chunk)
            tmp.replace(output)
        finally:
            tmp.unlink(missing_ok=True)
        return output

    def _save_browser_download_bytes(body: bytes, headers: dict[str, str], final_url: str) -> Path:
        output = _unique_browser_download_path(_browser_download_filename(headers, final_url))
        output.write_bytes(body)
        return output

    def _browser_download_saved_response(path: Path, source_url: str) -> Response:
        rel = path.relative_to(browser_downloads_root.resolve()).as_posix()
        file_name = path.name
        download_url = url_for("api_browser_download_file") + "?path=" + url_parse.quote(rel)
        preview_url = url_for("api_browser_download_file") + "?inline=1&path=" + url_parse.quote(rel)
        html_body = f"""<!doctype html>
<html lang="de">
<head><meta charset="utf-8"><title>Download gespeichert</title>
<style>body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#eef4ff;color:#162033;display:grid;place-items:center;min-height:100vh;margin:0}}main{{max-width:640px;background:white;border-radius:22px;padding:32px;box-shadow:0 20px 60px rgba(20,40,80,.16)}}code{{background:#edf2ff;padding:.15rem .35rem;border-radius:.35rem}}a{{color:#0b63ce}}</style></head>
<body><main>
<h1>Download gespeichert</h1>
<p><strong>{html.escape(file_name)}</strong> wurde in <code>{html.escape(BROWSER_DOWNLOADS_FOLDER)}</code> gespeichert.</p>
<p><a href="{html.escape(preview_url, quote=True)}">Öffnen</a> · <a href="{html.escape(download_url, quote=True)}">Als Datei herunterladen</a></p>
<p style="color:#64748b;font-size:.92rem">Quelle: {html.escape(source_url)}</p>
<script>try{{window.parent.postMessage({{type:'dcloud-browser-download-saved',fileName:{json.dumps(file_name)},folder:{json.dumps(BROWSER_DOWNLOADS_FOLDER)}}}, '*');}}catch(e){{}}</script>
</main></body></html>"""
        response = Response(html_body, status=200, content_type="text/html; charset=utf-8")
        response.headers["Cache-Control"] = "no-store"
        return response

    def _proxy_response_from_bytes(body: bytes, *, status: int = 200, headers: dict[str, str] | None = None, base_url: str = "", native_mode: bool = False) -> Response:
        source_headers = headers or {}
        content_type = source_headers.get("Content-Type") or source_headers.get("content-type") or "application/octet-stream"
        out_body = body
        lower_content_type = content_type.lower()
        if base_url and _browser_response_should_save_download(source_headers, base_url):
            output = _save_browser_download_bytes(body, source_headers, base_url)
            return _browser_download_saved_response(output, base_url)
        if base_url and "text/html" in lower_content_type and _is_google_host(url_parse.urlsplit(base_url).hostname or "") and _is_google_captcha_body(body):
            parsed_google = url_parse.urlsplit(base_url)
            google_query = url_parse.parse_qs(parsed_google.query).get("q", [""])[0]
            return _google_proxy_notice_response(base_url, query=google_query, details="Google hat eine CAPTCHA-/Domain-Prüfung ausgeliefert, die im serverseitigen Proxy nicht gültig abgeschlossen werden kann.")
        if "text/html" in lower_content_type and base_url:
            out_body = _rewrite_browser_html(body, base_url, native_mode=native_mode)
            content_type = "text/html; charset=utf-8"
        elif "text/css" in lower_content_type and base_url:
            text = body.decode("utf-8", errors="replace")
            out_body = _rewrite_browser_css(text, base_url, native_mode=native_mode).encode("utf-8")
            content_type = "text/css; charset=utf-8"
        elif base_url and ("javascript" in lower_content_type or "ecmascript" in lower_content_type or url_parse.urlsplit(base_url).path.lower().endswith((".js", ".mjs"))):
            text = body.decode("utf-8", errors="replace")
            out_body = _rewrite_browser_js(text, base_url, native_mode=native_mode).encode("utf-8")
            content_type = "application/javascript; charset=utf-8"
        response = Response(out_body, status=status, content_type=content_type)
        for key, value in source_headers.items():
            lower = key.lower()
            if lower in {"cache-control", "expires", "last-modified", "etag"}:
                response.headers[key] = value
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Access-Control-Allow-Origin"] = "null"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, HEAD, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Accept"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

    def _browser_forward_request_parts() -> tuple[str, bytes, dict[str, str]]:
        method = request.method.upper()
        if method not in {"GET", "POST", "HEAD"}:
            method = "GET"
        body = request.get_data() if method == "POST" else b""
        headers = {
            "User-Agent": request.headers.get("User-Agent") or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 dcloud-server-browser/1.0",
            "Accept": request.headers.get("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            "Accept-Language": request.headers.get("Accept-Language", "de-DE,de;q=0.9,en;q=0.8"),
            "Accept-Encoding": "identity",
        }
        if method == "POST":
            if request.headers.get("Content-Type"):
                headers["Content-Type"] = request.headers.get("Content-Type", "")
            headers["Content-Length"] = str(len(body))
        return method, body, headers

    def _fetch_external_browser_url(url: str, *, native_mode: bool = False) -> Response:
        try:
            _validate_external_browser_target(url)
        except StorageError as exc:
            return Response(str(exc), status=403, content_type="text/plain; charset=utf-8")
        parsed = url_parse.urlsplit(url)
        hostname = (parsed.hostname or "").lower()
        if _is_google_host(hostname):
            params = url_parse.parse_qs(parsed.query, keep_blank_values=True)
            google_result_target = (params.get("q") or params.get("url") or [""])[0]
            if parsed.path.rstrip("/") == "/url" and google_result_target.startswith(("http://", "https://")):
                return redirect(_browser_proxy_url_for(google_result_target, native_mode=native_mode), code=302)
            if parsed.path.rstrip("/") in {"", "/search"} and params.get("q"):
                return redirect(_browser_proxy_url_for(_safe_search_url(params.get("q", [""])[0]), native_mode=native_mode), code=302)
            if parsed.path in {"", "/"} or parsed.path.startswith(("/sorry", "/recaptcha")):
                return _google_proxy_notice_response(url, query=(params.get("q") or [""])[0])
        method, body, headers = _browser_forward_request_parts()
        req = url_request.Request(
            url,
            data=body if method == "POST" else None,
            headers=headers,
            method=method,
        )
        try:
            with browser_http_opener.open(req, timeout=18) as remote:
                headers = {str(k): str(v) for k, v in remote.headers.items()}
                final_url = str(remote.geturl() or url)
                if _browser_response_should_save_download(headers, final_url):
                    output = _save_browser_download_stream(remote, headers, final_url)
                    return _browser_download_saved_response(output, final_url)
                body = remote.read(16 * 1024 * 1024)
                return _proxy_response_from_bytes(body, status=int(remote.status), headers=headers, base_url=final_url, native_mode=native_mode)
        except url_error.HTTPError as exc:
            body = exc.read(2 * 1024 * 1024)
            headers = {str(k): str(v) for k, v in exc.headers.items()}
            location = headers.get("Location") or headers.get("location")
            if location and 300 <= int(exc.code) < 400:
                absolute_location = url_parse.urljoin(url, location)
                try:
                    _validate_external_browser_target(absolute_location)
                except StorageError as validation_error:
                    return Response(str(validation_error), status=403, content_type="text/plain; charset=utf-8")
                redirected = _browser_proxy_target(absolute_location, url, native_mode=native_mode)
                return redirect(redirected, code=302)
            return _proxy_response_from_bytes(body, status=int(exc.code), headers=headers, base_url=url, native_mode=native_mode)
        except Exception as exc:
            return Response(f"Seite konnte nicht geladen werden: {exc}", status=502, content_type="text/plain; charset=utf-8")

    def _fetch_peer_dcloud_site(peer: Any, parsed: Any, original_url: str, *, native_mode: bool = False) -> Response:
        site_path = parsed.path or "/"
        relay_path = "/dcloud-site" + (site_path if site_path.startswith("/") else "/" + site_path)
        if parsed.query:
            relay_path += "?" + parsed.query
        method, body, headers = _browser_forward_request_parts()
        if getattr(peer, "host", "") and getattr(peer, "host", "") != "__relay__":
            port = int(getattr(peer, "web_port", None) or config.web.port)
            direct_url = f"http://{getattr(peer, 'host')}:{port}{relay_path}"
            try:
                with url_request.urlopen(url_request.Request(direct_url, data=body if method == "POST" else None, headers=headers, method=method), timeout=10) as remote:
                    body = remote.read(8 * 1024 * 1024)
                    headers = {str(k): str(v) for k, v in remote.headers.items()}
                    return _proxy_response_from_bytes(body, status=int(remote.status), headers=headers, base_url=original_url, native_mode=native_mode)
            except Exception:
                pass
        relay_url = str(getattr(peer, "relay_url", "") or "").rstrip("/")
        with relay_lock:
            relay_client = relay_clients.get(relay_url)
        if relay_client is not None:
            last_relay_error = ""
            try:
                relay_response = relay_client.direct_proxy_request(
                    peer,
                    method=method,
                    path=relay_path,
                    headers=headers,
                    body=body,
                    timeout=20,
                )
                if int(relay_response.status_code) < 500:
                    return _proxy_response_from_bytes(
                        relay_response.body,
                        status=relay_response.status_code,
                        headers=relay_response.headers,
                        base_url=original_url,
                        native_mode=native_mode,
                    )
                preview = relay_response.body.decode("utf-8", errors="replace").strip().replace("\n", " ")[:240]
                last_relay_error = f"direkter Peer-Forward lieferte HTTP {relay_response.status_code}: {preview or 'keine Details'}"
            except Exception as exc:
                last_relay_error = str(exc)
            try:
                relay_response = relay_client.forward_request(
                    peer,
                    method=method,
                    path=relay_path,
                    headers=headers,
                    body=body,
                    timeout=20,
                )
                return _proxy_response_from_bytes(
                    relay_response.body,
                    status=relay_response.status_code,
                    headers=relay_response.headers,
                    base_url=original_url,
                    native_mode=native_mode,
                )
            except Exception as exc:
                details = str(exc)
                if last_relay_error and last_relay_error != details:
                    details = f"{details} (direkter Peer-Forward vorher: {last_relay_error})"
                return Response(f"Peer-Webseite über direkte Route nicht erreichbar: {details}", status=502, content_type="text/plain; charset=utf-8")
        return Response("Peer-Webseite ist aktuell nicht erreichbar.", status=502, content_type="text/plain; charset=utf-8")

    def _fetch_dcloud_browser_url(url: str, *, native_mode: bool = False) -> Response:
        parsed = url_parse.urlsplit(url)
        hostname = (parsed.hostname or "").lower()
        try:
            target_kind, peer = _resolve_dcloud_peer(hostname)
        except StorageError as exc:
            return Response(str(exc), status=404, content_type="text/plain; charset=utf-8")
        if target_kind == "local":
            response = _serve_local_web_path(parsed.path or "/", query_string=parsed.query)
            response_headers = dict(response.headers)
            if response.content_type and "text/html" in response.content_type.lower():
                response.direct_passthrough = False
                body = response.get_data()
                return _proxy_response_from_bytes(body, status=response.status_code, headers=response_headers, base_url=url, native_mode=native_mode)
            if _browser_response_should_save_download(response_headers, url):
                response.direct_passthrough = False
                body = response.get_data()
                return _proxy_response_from_bytes(body, status=response.status_code, headers=response_headers, base_url=url, native_mode=native_mode)
            return response
        return _fetch_peer_dcloud_site(peer, parsed, url, native_mode=native_mode)



    def _local_dashboard_base_url() -> str:
        host = str(getattr(config.web, "host", "127.0.0.1") or "127.0.0.1")
        if host in {"0.0.0.0", "::", ""}:
            host = "127.0.0.1"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"http://{host}:{int(config.web.port)}"

    def web_hosting_payload(peers: list[Any] | None = None) -> dict[str, Any]:
        peer_items = []
        for peer in (peers if peers is not None else _list_active_peers()):
            names = [f"{candidate}.dcloud" for candidate in _web_host_candidates(peer.node_id, getattr(peer, "name", None))]
            peer_items.append(
                {
                    "nodeId": peer.node_id,
                    "displayName": display_name_for_peer(peer.node_id, getattr(peer, "name", None)),
                    "hostnames": names,
                    "primaryHost": names[0] if names else "",
                }
            )
        local_names = [f"{candidate}.dcloud" for candidate in _web_host_candidates(identity.node_id, config.node.name)]
        return {
            "enabled": True,
            "webRoot": str(web_root),
            "localHostnames": local_names,
            "primaryHost": local_names[0] if local_names else _primary_web_hostname(),
            "localUrl": f"http://{local_names[0] if local_names else _primary_web_hostname()}/",
            "phpAvailable": bool(_php_binary()),
            "phpBinary": _php_binary(),
            "serverProxyAvailable": True,
            "browserProxyToken": browser_access_token,
            "peers": peer_items,
        }

    _ensure_web_root()
    _ensure_browser_downloads_root()

    def _sanitize_chat_alias(value: Any) -> str:
        alias = str(value or "").strip()
        alias = re.sub(r"[\r\n\t]+", " ", alias)
        alias = re.sub(r"\s{2,}", " ", alias)
        return alias[:48]

    def _default_chat_alias() -> str:
        return display_name_for_peer(identity.node_id, config.node.name)

    def _load_chat_settings() -> None:
        nonlocal chat_settings
        try:
            with chat_settings_path.open("r", encoding="utf-8") as handle:
                raw = json.load(handle)
            if not isinstance(raw, dict):
                raise ValueError("invalid chat settings")
            chat_settings = {
                "enabled": bool(raw.get("enabled", True)),
                "alias": _sanitize_chat_alias(raw.get("alias") or ""),
            }
        except FileNotFoundError:
            chat_settings = {"enabled": True, "alias": ""}
        except Exception:
            chat_settings = {"enabled": True, "alias": ""}

    def _persist_chat_settings() -> None:
        chat_settings_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(chat_settings, ensure_ascii=False, indent=2, sort_keys=True)
        tmp_path = chat_settings_path.with_suffix(".tmp")
        tmp_path.write_text(payload, encoding="utf-8")
        tmp_path.replace(chat_settings_path)

    def _chat_enabled() -> bool:
        return bool(chat_settings.get("enabled", True))

    def _chat_alias() -> str:
        return _sanitize_chat_alias(chat_settings.get("alias")) or _default_chat_alias()

    _load_chat_settings()

    def _load_disabled_peers() -> None:
        """Load user-disabled peers that discovery must not re-add to the UI."""
        nonlocal disabled_peers
        try:
            with disabled_peers_path.open("r", encoding="utf-8") as handle:
                raw = json.load(handle)
            if not isinstance(raw, dict):
                disabled_peers = {}
                return
            loaded: dict[str, dict[str, Any]] = {}
            for node_id, item in raw.items():
                safe_id = _safe_peer_id(str(node_id))
                if not safe_id or safe_id == identity.node_id or not isinstance(item, dict):
                    continue
                loaded[safe_id] = {
                    "node_id": safe_id,
                    "display_name": str(item.get("display_name") or item.get("name") or safe_id[:12]),
                    "disabled_at": float(item.get("disabled_at") or time.time()),
                    "last_host": str(item.get("last_host") or ""),
                    "last_relay_url": str(item.get("last_relay_url") or ""),
                }
            disabled_peers = loaded
        except FileNotFoundError:
            disabled_peers = {}
        except Exception:
            disabled_peers = {}

    def _persist_disabled_peers() -> None:
        disabled_peers_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(disabled_peers, ensure_ascii=False, indent=2, sort_keys=True)
        tmp_path = disabled_peers_path.with_suffix(".tmp")
        tmp_path.write_text(payload, encoding="utf-8")
        tmp_path.replace(disabled_peers_path)

    def _disabled_peer_ids() -> set[str]:
        with disabled_peer_lock:
            return set(disabled_peers)

    def _disabled_peers_payload() -> list[dict[str, Any]]:
        now = time.time()
        with disabled_peer_lock:
            items = list(disabled_peers.values())
        return sorted(
            [
                {
                    "node_id": str(item.get("node_id") or ""),
                    "display_name": str(item.get("display_name") or item.get("node_id") or "Peer"),
                    "disabled_at": float(item.get("disabled_at") or now),
                    "disabled_age_seconds": max(0.0, round(now - float(item.get("disabled_at") or now), 1)),
                    "last_host": str(item.get("last_host") or ""),
                    "last_relay_url": str(item.get("last_relay_url") or ""),
                }
                for item in items
                if str(item.get("node_id") or "")
            ],
            key=lambda item: float(item.get("disabled_at") or 0),
            reverse=True,
        )

    def _disable_peer(node_id: str, peer: Any | None = None) -> None:
        safe_id = _safe_peer_id(node_id)
        if not safe_id or safe_id == identity.node_id:
            raise ValueError("Peer-ID ist ungültig")
        display_name = display_name_for_peer(safe_id, getattr(peer, "name", None))
        if peer is not None:
            try:
                peer_dict = peer.to_dict()
                display_name = str(peer_dict.get("display_name") or display_name)
            except Exception:
                pass
        with disabled_peer_lock:
            disabled_peers[safe_id] = {
                "node_id": safe_id,
                "display_name": display_name,
                "disabled_at": time.time(),
                "last_host": str(getattr(peer, "host", "") or ""),
                "last_relay_url": str(getattr(peer, "relay_url", "") or ""),
            }
            _persist_disabled_peers()
        try:
            peer_provider.remove(safe_id)
        except Exception:
            pass

    def _enable_peer(node_id: str) -> bool:
        safe_id = _safe_peer_id(node_id)
        if not safe_id:
            return False
        with disabled_peer_lock:
            removed = disabled_peers.pop(safe_id, None) is not None
            if removed:
                _persist_disabled_peers()
        return removed

    def _normalize_direct_peer_url(value: Any) -> str:
        raw = str(value or "").strip().rstrip("/")
        if not raw:
            raise ValueError("NAT-/DDNS-Endpunkt fehlt")
        if not raw.lower().startswith(("http://", "https://")):
            raw = "http://" + raw
        try:
            parsed = url_parse.urlsplit(raw)
        except Exception as exc:
            raise ValueError("NAT-/DDNS-Endpunkt ist keine gültige URL") from exc
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("Nur http:// oder https:// sind als Peer-Endpunkt erlaubt")
        host = (parsed.hostname or "").strip().strip("[]")
        if not host:
            raise ValueError("Peer-Endpunkt benötigt einen Hostnamen oder eine IP")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Peer-Endpunkt enthält einen ungültigen Port") from exc
        if port is None:
            port = 443 if scheme == "https" else int(getattr(config.web, "port", 8787) or 8787)
        if not 1 <= int(port) <= 65535:
            raise ValueError("Peer-Port muss zwischen 1 und 65535 liegen")
        host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
        default_port = 443 if scheme == "https" else 80
        netloc = host_part if int(port) == default_port else f"{host_part}:{int(port)}"
        return f"{scheme}://{netloc}"

    def _manual_route_to_peer(route: dict[str, Any]) -> Peer | None:
        node_id = _safe_peer_id(str(route.get("node_id") or ""))
        urls = [str(url) for url in route.get("urls", []) if str(url)] if isinstance(route.get("urls"), list) else []
        if not node_id or not urls:
            return None
        url = urls[0]
        try:
            parsed = url_parse.urlsplit(url)
            host = (parsed.hostname or "").strip().strip("[]")
            if not host:
                return None
            port = parsed.port or (443 if parsed.scheme == "https" else int(getattr(config.web, "port", 8787) or 8787))
        except Exception:
            return None
        via_gateway = _safe_peer_id(str(route.get("via_gateway_node_id") or ""))
        gateway_name = str(route.get("gateway_display_name") or "").strip() or None
        return Peer(
            node_id=node_id,
            host=host,
            udp_port=0,
            name=str(route.get("display_name") or route.get("name") or "") or None,
            route_via_node_id=via_gateway,
            gateway_node_id=via_gateway,
            gateway_display_name=gateway_name,
            gateway_public_urls=urls if via_gateway else [],
            web_port=int(port),
            public_host=host,
            public_port=int(port),
            public_urls=urls,
            scheme=(parsed.scheme or "http").lower(),
            client_type=str(route.get("client_type") or "server") if str(route.get("client_type") or "server") in {"server"} else None,
            accepts_peer_storage=bool(route.get("accepts_peer_storage", True)),
            shared_storage_bytes=int(route.get("shared_storage_bytes") or 0) or None,
            free_storage_bytes=int(route.get("free_storage_bytes") or route.get("shared_storage_bytes") or 0) or None,
        )

    def _load_manual_peer_routes() -> None:
        nonlocal manual_peer_routes
        try:
            with manual_peer_routes_path.open("r", encoding="utf-8") as handle:
                raw = json.load(handle)
            if not isinstance(raw, dict):
                manual_peer_routes = {}
                return
            loaded: dict[str, dict[str, Any]] = {}
            for node_id, item in raw.items():
                safe_id = _safe_peer_id(str(node_id))
                if not safe_id or safe_id == identity.node_id or not isinstance(item, dict):
                    continue
                urls: list[str] = []
                raw_urls = item.get("urls") if isinstance(item.get("urls"), list) else [item.get("url") or item.get("endpoint")]
                for raw_url in raw_urls:
                    try:
                        normalized = _normalize_direct_peer_url(raw_url)
                    except ValueError:
                        continue
                    if normalized not in urls:
                        urls.append(normalized)
                if not urls:
                    continue
                via_gateway = _safe_peer_id(str(item.get("via_gateway_node_id") or ""))
                loaded[safe_id] = {
                    "node_id": safe_id,
                    "display_name": str(item.get("display_name") or item.get("name") or safe_id[:12]),
                    "urls": urls[:8],
                    "created_at": float(item.get("created_at") or time.time()),
                    "updated_at": float(item.get("updated_at") or time.time()),
                    "last_ok_at": float(item.get("last_ok_at") or 0),
                    "last_error": str(item.get("last_error") or ""),
                    "via_gateway_node_id": via_gateway or "",
                    "gateway_display_name": str(item.get("gateway_display_name") or ""),
                    "source": "gateway" if via_gateway else "manual",
                    "client_type": str(item.get("client_type") or "server"),
                    "accepts_peer_storage": bool(item.get("accepts_peer_storage", True)),
                    "shared_storage_bytes": int(item.get("shared_storage_bytes") or 0),
                    "free_storage_bytes": int(item.get("free_storage_bytes") or item.get("shared_storage_bytes") or 0),
                }
            manual_peer_routes = loaded
        except FileNotFoundError:
            manual_peer_routes = {}
        except Exception:
            manual_peer_routes = {}

    def _persist_manual_peer_routes() -> None:
        manual_peer_routes_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(manual_peer_routes, ensure_ascii=False, indent=2, sort_keys=True)
        tmp_path = manual_peer_routes_path.with_suffix(".tmp")
        tmp_path.write_text(payload, encoding="utf-8")
        tmp_path.replace(manual_peer_routes_path)

    def _probe_direct_peer_endpoint(endpoint: str, *, timeout: float = 4.0) -> tuple[Peer, dict[str, Any]]:
        url = _normalize_direct_peer_url(endpoint)
        parsed = url_parse.urlsplit(url)
        health_url = url + "/healthz"
        req = url_request.Request(health_url, headers={"Accept": "application/json"}, method="GET")
        try:
            with url_request.urlopen(req, timeout=timeout) as response:
                body = response.read(64 * 1024)
        except Exception as exc:
            raise StorageError(f"Direkter Peer-Endpunkt nicht erreichbar: {exc}") from exc
        try:
            payload = json.loads(body.decode("utf-8", errors="replace"))
        except Exception as exc:
            raise StorageError("Peer-Endpunkt antwortet nicht mit gültigem /healthz JSON") from exc
        if not isinstance(payload, dict) or str(payload.get("status") or "").lower() != "ok":
            raise StorageError("Peer-Endpunkt ist kein gültiger dcloud-Peer")
        node_id = _safe_peer_id(str(payload.get("node_id") or ""))
        if not node_id:
            raise StorageError("Peer-Endpunkt liefert keine Node-ID")
        if node_id == identity.node_id:
            raise StorageError("Der NAT-Endpunkt zeigt auf diesen eigenen Knoten")
        host = (parsed.hostname or "").strip().strip("[]")
        port = parsed.port or (443 if parsed.scheme == "https" else int(getattr(config.web, "port", 8787) or 8787))
        peer = Peer(
            node_id=node_id,
            host=host,
            udp_port=0,
            name=str(payload.get("name") or payload.get("display_name") or "") or None,
            web_port=int(port),
            public_host=host,
            public_port=int(port),
            public_urls=[url],
            scheme=(parsed.scheme or "http").lower(),
            client_type=str(payload.get("client_type") or "server") if str(payload.get("client_type") or "server") in {"server"} else None,
            shared_storage_bytes=int(payload.get("shared_storage_bytes") or 0) or None,
            free_storage_bytes=int(payload.get("free_storage_bytes") or payload.get("shared_storage_bytes") or 0) or None,
            accepts_peer_storage=bool(payload.get("accepts_peer_storage", True)),
        )
        return peer, payload

    def _upsert_manual_peer_route(endpoint: str, *, display_name: str | None = None) -> Peer:
        peer, payload = _probe_direct_peer_endpoint(endpoint)
        normalized_url = _normalize_direct_peer_url(endpoint)
        now = time.time()
        label = (display_name or str(payload.get("name") or "") or display_name_for_peer(peer.node_id, peer.name)).strip()
        with manual_peer_routes_lock:
            existing = manual_peer_routes.get(peer.node_id, {})
            urls = [str(url) for url in existing.get("urls", []) if str(url)] if isinstance(existing.get("urls"), list) else []
            if normalized_url not in urls:
                urls.insert(0, normalized_url)
            manual_peer_routes[peer.node_id] = {
                "node_id": peer.node_id,
                "display_name": label,
                "urls": urls[:16],
                "created_at": float(existing.get("created_at") or now),
                "updated_at": now,
                "last_ok_at": now,
                "last_error": "",
                "source": "manual",
                "client_type": str(payload.get("client_type") or "server"),
                "accepts_peer_storage": bool(payload.get("accepts_peer_storage", True)),
                "shared_storage_bytes": int(payload.get("shared_storage_bytes") or 0),
                "free_storage_bytes": int(payload.get("free_storage_bytes") or payload.get("shared_storage_bytes") or 0),
            }
            _persist_manual_peer_routes()
        peer_provider.add_or_update(peer)
        try:
            _perform_peer_exchange(peer, force=True)
        except Exception:
            LOG.debug("Active Direct-Peer exchange with %s failed", peer.node_id, exc_info=True)
            try:
                _sync_gateway_peers_from_peer(peer, force=True)
            except Exception:
                LOG.debug("Gateway peer discovery from %s failed", peer.node_id, exc_info=True)
        return peer

    def _manual_peer_routes_payload() -> list[dict[str, Any]]:
        with manual_peer_routes_lock:
            routes = [dict(route) for route in manual_peer_routes.values()]
        active_ids = {str(getattr(peer, "node_id", "") or "") for peer in peer_provider.list_peers()}
        return sorted(
            [
                {
                    "node_id": str(route.get("node_id") or ""),
                    "display_name": str(route.get("display_name") or route.get("node_id") or "Peer"),
                    "urls": list(route.get("urls") or []),
                    "updated_at": float(route.get("updated_at") or 0),
                    "last_ok_at": float(route.get("last_ok_at") or 0),
                    "last_error": str(route.get("last_error") or ""),
                    "active": str(route.get("node_id") or "") in active_ids,
                    "via_gateway_node_id": str(route.get("via_gateway_node_id") or ""),
                    "gateway_display_name": str(route.get("gateway_display_name") or ""),
                    "source": str(route.get("source") or ("gateway" if route.get("via_gateway_node_id") else "manual")),
                    "shared_storage_bytes": int(route.get("shared_storage_bytes") or 0),
                    "free_storage_bytes": int(route.get("free_storage_bytes") or route.get("shared_storage_bytes") or 0),
                    "accepts_peer_storage": bool(route.get("accepts_peer_storage", True)),
                }
                for route in routes
                if str(route.get("node_id") or "")
            ],
            key=lambda item: str(item.get("display_name") or "").lower(),
        )

    def _gateway_urls_for_peer(peer: Peer) -> list[str]:
        urls: list[str] = []
        for raw in list(getattr(peer, "public_urls", []) or []):
            try:
                normalized = _normalize_direct_peer_url(raw)
            except ValueError:
                continue
            if normalized not in urls:
                urls.append(normalized)
        if not urls:
            scheme = str(getattr(peer, "scheme", None) or "http").lower()
            host = str(getattr(peer, "host", "") or "").strip().strip("[]")
            port = int(getattr(peer, "web_port", 0) or getattr(config.web, "port", 8787) or 8787)
            if host and host != RELAY_HOST:
                host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
                default_port = 443 if scheme == "https" else 80
                urls.append(f"{scheme}://{host_part}" if port == default_port else f"{scheme}://{host_part}:{port}")
        return urls[:8]

    def _store_gateway_peer_route(gateway_peer: Peer, peer_info: dict[str, Any]) -> bool:
        node_id = _safe_peer_id(str(peer_info.get("node_id") or ""))
        if not node_id or node_id in {identity.node_id, gateway_peer.node_id}:
            return False
        if node_id in _disabled_peer_ids():
            return False
        gateway_urls = _gateway_urls_for_peer(gateway_peer)
        if not gateway_urls:
            return False
        now = time.time()
        display_name = str(peer_info.get("display_name") or peer_info.get("name") or display_name_for_peer(node_id)).strip()
        gateway_label = display_name_for_peer(gateway_peer.node_id, gateway_peer.name)
        with manual_peer_routes_lock:
            existing = manual_peer_routes.get(node_id, {})
            # A manually configured direct endpoint is stronger than a learned
            # gateway route. Keep it and only refresh gateway metadata if it was
            # already a gateway entry.
            if existing and not existing.get("via_gateway_node_id"):
                return False
            manual_peer_routes[node_id] = {
                "node_id": node_id,
                "display_name": display_name,
                "urls": gateway_urls,
                "created_at": float(existing.get("created_at") or now),
                "updated_at": now,
                "last_ok_at": now,
                "last_error": "",
                "via_gateway_node_id": gateway_peer.node_id,
                "gateway_display_name": gateway_label,
                "source": "gateway",
                "client_type": str(peer_info.get("client_type") or "server"),
                "accepts_peer_storage": bool(peer_info.get("accepts_peer_storage", True)),
                "shared_storage_bytes": int(peer_info.get("shared_storage_bytes") or 0),
                "free_storage_bytes": int(peer_info.get("free_storage_bytes") or peer_info.get("shared_storage_bytes") or 0),
            }
            _persist_manual_peer_routes()
            route = dict(manual_peer_routes[node_id])
        routed_peer = _manual_route_to_peer(route)
        if routed_peer is not None:
            peer_provider.add_or_update(routed_peer)
        return True

    def _sync_gateway_peers_from_peer(gateway_peer: Peer, *, force: bool = False) -> int:
        if not gateway_peer or getattr(gateway_peer, "route_via_node_id", None):
            return 0
        try:
            known_peers = p2p_client.get_known_peers(gateway_peer)
        except Exception:
            if force:
                LOG.debug("Gateway peer-list request to %s failed", gateway_peer.node_id, exc_info=True)
            return 0
        count = 0
        for peer_info in known_peers:
            try:
                if _store_gateway_peer_route(gateway_peer, peer_info):
                    count += 1
            except Exception:
                LOG.debug("Could not store gateway peer route from %s", gateway_peer.node_id, exc_info=True)
        return count

    def _refresh_manual_peer_routes(*, force: bool = False, min_interval_seconds: float = 20.0) -> None:
        nonlocal last_manual_peer_route_refresh_at
        now = time.time()
        if not force and last_manual_peer_route_refresh_at and now - last_manual_peer_route_refresh_at < min_interval_seconds:
            return
        last_manual_peer_route_refresh_at = now
        with manual_peer_routes_lock:
            route_items = [dict(route) for route in manual_peer_routes.values()]
        changed = False
        active_by_id = {peer.node_id: peer for peer in peer_provider.list_peers()}
        for route in route_items:
            node_id = _safe_peer_id(str(route.get("node_id") or ""))
            urls = [str(url) for url in route.get("urls", []) if str(url)] if isinstance(route.get("urls"), list) else []
            if not node_id or not urls:
                continue
            via_gateway = _safe_peer_id(str(route.get("via_gateway_node_id") or ""))
            if via_gateway:
                gateway_peer = active_by_id.get(via_gateway)
                routed_peer = _manual_route_to_peer(route)
                if gateway_peer is not None and routed_peer is not None:
                    peer_provider.add_or_update(routed_peer)
                    with manual_peer_routes_lock:
                        current = manual_peer_routes.get(node_id)
                        if current is not None:
                            current["last_ok_at"] = now
                            current["last_error"] = ""
                            changed = True
                else:
                    with manual_peer_routes_lock:
                        current = manual_peer_routes.get(node_id)
                        if current is not None:
                            current["last_error"] = "Gateway aktuell nicht erreichbar"
                            changed = True
                continue
            last_error = ""
            for endpoint in urls:
                try:
                    peer, payload = _probe_direct_peer_endpoint(endpoint, timeout=2.5)
                    if peer.node_id != node_id:
                        last_error = "Endpunkt meldet eine andere Node-ID"
                        continue
                    peer_provider.add_or_update(peer)
                    active_by_id[peer.node_id] = peer
                    try:
                        _perform_peer_exchange(peer)
                    except Exception:
                        LOG.debug("Active Direct-Peer exchange refresh with %s failed", peer.node_id, exc_info=True)
                        try:
                            _sync_gateway_peers_from_peer(peer)
                        except Exception:
                            LOG.debug("Gateway peer-list refresh from %s failed", peer.node_id, exc_info=True)
                    with manual_peer_routes_lock:
                        current = manual_peer_routes.get(node_id)
                        if current is not None:
                            current["last_ok_at"] = now
                            current["last_error"] = ""
                            current["display_name"] = str(current.get("display_name") or payload.get("name") or display_name_for_peer(node_id, peer.name))
                            current["client_type"] = str(payload.get("client_type") or "server")
                            current["accepts_peer_storage"] = bool(payload.get("accepts_peer_storage", True))
                            current["shared_storage_bytes"] = int(payload.get("shared_storage_bytes") or 0)
                            current["free_storage_bytes"] = int(payload.get("free_storage_bytes") or payload.get("shared_storage_bytes") or 0)
                            changed = True
                    break
                except Exception as exc:
                    last_error = str(exc)
            else:
                with manual_peer_routes_lock:
                    current = manual_peer_routes.get(node_id)
                    if current is not None:
                        current["last_error"] = last_error[:300]
                        changed = True
        if changed:
            with manual_peer_routes_lock:
                _persist_manual_peer_routes()



    def _load_external_download_links() -> None:
        """Load temporary external download links from the runtime store."""
        nonlocal external_download_links
        try:
            with external_links_path.open("r", encoding="utf-8") as handle:
                raw = json.load(handle)
            if not isinstance(raw, dict):
                return
            now = time.time()
            loaded: dict[str, dict[str, Any]] = {}
            for token, item in raw.items():
                if not isinstance(token, str) or not isinstance(item, dict):
                    continue
                expires_at = float(item.get("expires_at") or 0)
                manifest_id = str(item.get("manifest_id") or "")
                if token and manifest_id and expires_at > now:
                    loaded[token] = {
                        "manifest_id": manifest_id,
                        "file_name": str(item.get("file_name") or "download.bin"),
                        "created_at": float(item.get("created_at") or now),
                        "expires_at": expires_at,
                        "created_by": str(item.get("created_by") or ""),
                    }
            external_download_links = loaded
        except FileNotFoundError:
            external_download_links = {}
        except Exception:
            external_download_links = {}

    def _persist_external_download_links() -> None:
        external_links_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(external_download_links, ensure_ascii=False, indent=2, sort_keys=True)
        tmp_path = external_links_path.with_suffix(".tmp")
        tmp_path.write_text(payload, encoding="utf-8")
        tmp_path.replace(external_links_path)

    def _cleanup_external_download_links(*, persist: bool = True) -> int:
        now = time.time()
        removed = 0
        for token, item in list(external_download_links.items()):
            try:
                expires_at = float(item.get("expires_at") or 0)
            except Exception:
                expires_at = 0
            if expires_at <= now:
                external_download_links.pop(token, None)
                removed += 1
        if removed and persist:
            _persist_external_download_links()
        return removed

    def _parse_external_link_minutes(value: Any) -> int:
        try:
            minutes = int(float(value))
        except Exception:
            minutes = 60
        return max(1, min(60, minutes))


    def _create_relay_external_download_links(
        *,
        local_token: str,
        manifest: FileManifest,
        expires_at: float,
        ttl_seconds: int,
    ) -> list[dict[str, Any]]:
        return []

    with disabled_peer_lock:
        _load_disabled_peers()

    with manual_peer_routes_lock:
        _load_manual_peer_routes()

    with external_link_lock:
        _load_external_download_links()
        _cleanup_external_download_links(persist=True)

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
            try:
                removed_size = chunk_path.stat().st_size
            except OSError:
                removed_size = None
            chunk_path.unlink(missing_ok=True)
            chunk_store.note_chunk_removed(removed_size)
            removed_unreferenced_chunks += 1

        for tmp_path in chunk_store.tmp_dir.glob("*"):
            if not tmp_path.is_file():
                continue
            if tmp_path == external_links_path or tmp_path == external_links_path.with_suffix(".tmp"):
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

    def _current_user() -> dict[str, Any] | None:
        username = str(session.get("dcloud_username") or "")
        if not username:
            return None
        user = user_store.get(username)
        if user is None or not user.enabled:
            session.clear()
            return None
        return user.to_public_dict()

    def _current_username() -> str:
        user = _current_user()
        return str(user.get("username") or "") if user else ""

    def _current_user_is_admin() -> bool:
        user = _current_user()
        return bool(user and user.get("role") == "admin")

    def _auth_payload() -> dict[str, Any]:
        user = _current_user()
        return {
            "setupRequired": not user_store.has_users(),
            "authenticated": bool(user),
            "currentUser": user,
            "isAdmin": bool(user and user.get("role") == "admin"),
        }

    def _wants_json_response() -> bool:
        return request.path.startswith("/api/") or _is_ajax_request()

    def _auth_error(message: str = "Bitte zuerst anmelden", status: int = 401) -> Response:
        if _wants_json_response():
            return jsonify({"ok": False, "message": message}), status
        return redirect(url_for("login", next=request.path))

    def _require_admin() -> Response | None:
        if not _current_user_is_admin():
            return _auth_error("Nur Administratoren dürfen diese Aktion ausführen", 403)
        return None

    def _is_public_or_peer_path(path: str) -> bool:
        if request.method == "OPTIONS":
            return True
        if path in {"/login", "/setup", "/logout", "/healthz", "/favicon.ico"}:
            return True
        if path.startswith("/static/"):
            return True
        if path.startswith("/external/"):
            return True
        if path.startswith("/dcloud-site"):
            return True
        if path.startswith("/browser/view"):
            token = str(request.args.get("browser_token") or "")
            return bool(token and secrets.compare_digest(token, browser_access_token))
        # Peer/relay endpoints must stay reachable without dashboard login.
        if path.startswith("/api/p2p/"):
            return True
        return False

    @app.before_request
    def _dashboard_auth_guard() -> Response | None:
        path = request.path or "/"
        p2p_error = _verify_p2p_request_signature()
        if p2p_error is not None:
            return p2p_error
        csrf_error = _check_csrf_for_dashboard_request(path)
        if csrf_error is not None:
            return csrf_error
        if _is_public_or_peer_path(path):
            if path == "/setup" and user_store.has_users():
                return redirect(url_for("dashboard"))
            return None
        if not user_store.has_users():
            if _wants_json_response():
                return jsonify({"ok": False, "message": "Ersteinrichtung erforderlich", "setupRequired": True}), 401
            return redirect(url_for("setup"))
        if _current_user() is None:
            return _auth_error()
        return None

    @app.after_request
    def _security_headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
        if request.path.startswith("/browser/view"):
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
        return response

    @app.context_processor
    def _inject_auth_context() -> dict[str, Any]:
        return {"auth": _auth_payload(), "csrf_token": _csrf_token()}

    def _list_active_peers() -> list[Any]:
        _refresh_manual_peer_routes()
        if peer_connector is not None and hasattr(peer_connector, "prune_stale_peers"):
            peer_connector.prune_stale_peers()
        disabled_ids = _disabled_peer_ids()
        peers: list[Any] = []
        for peer in peer_provider.list_peers():
            node_id = str(getattr(peer, "node_id", "") or "")
            # The local node must never appear as a share/storage target. If a relay or
            # stale discovery packet reports our own node id, sending a shared manifest
            # back to ourselves can resurrect old manifest ids and duplicate files.
            if node_id == identity.node_id:
                continue
            # User-disabled peers stay hidden even when UDP discovery, gossip or the
            # PHP relay announces them again on the next refresh.  Remove the current
            # runtime entry as well so transfers cannot pick it in the same cycle.
            if node_id in disabled_ids:
                try:
                    peer_provider.remove(node_id)
                except Exception:
                    pass
                continue
            peers.append(peer)
        return peers

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
                status="Datei ist lokal gespeichert; Sicherheitskopie läuft per Direct-/Gateway-Upload im Hintergrund…",
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

    def _manifest_clone_with_chunks(manifest: FileManifest, chunks: list[dict[str, Any]], placement: dict[str, Any] | None = None) -> FileManifest:
        data = manifest.to_dict()
        data["chunks"] = [dict(chunk) for chunk in chunks]
        if placement is not None:
            data["placement"] = dict(placement)
        return FileManifest.from_dict(data)

    def _merge_peer_delegation_payload(result: Any, payload: dict[str, Any]) -> Any:
        chunks = payload.get("chunks")
        if isinstance(chunks, list) and len(chunks) == len(result.chunks) and all(isinstance(chunk, dict) for chunk in chunks):
            result.chunks = [dict(chunk) for chunk in chunks]
        targets = payload.get("targets")
        if isinstance(targets, list):
            result.targets = list(dict.fromkeys([
                *[str(item) for item in getattr(result, "targets", []) if str(item)],
                *[str(item) for item in targets if str(item)],
            ]))
        result.remote_successes += max(0, int(payload.get("remote_successes") or 0))
        result.remote_failures += max(0, int(payload.get("remote_failures") or 0))
        if "desired_replicas" in payload:
            result.desired_replicas = max(1, int(payload.get("desired_replicas") or result.desired_replicas))
        if "replicated_chunks" in payload:
            result.replicated_chunks = max(0, int(payload.get("replicated_chunks") or 0))
        if "under_replicated_chunks" in payload:
            result.under_replicated_chunks = max(0, int(payload.get("under_replicated_chunks") or 0))
        return result

    def _replicate_via_primary_peer(
        *,
        manifest: FileManifest,
        peers: list[Any],
        require_primary: bool = False,
        progress_callback: Any = None,
    ) -> tuple[Any, dict[str, Any]]:
        """Send chunks to one peer first; that peer fans out the RAID mirrors.

        This keeps the starter node from uploading the same chunk data to every
        mirror.  If the delegated endpoint is not available yet, the primary
        copy is still created and the caller can decide whether that is enough.
        """
        ranked = rank_peers_by_speed(peers, p2p_client) if peers else []
        if not ranked:
            raise StorageError("Keine aktiven Speicher-Peers verfügbar")
        primary = ranked[0]
        initial = replicate_manifest_chunks(
            manifest=manifest,
            chunk_store=chunk_store,
            local_node_id=identity.node_id,
            peers=[primary],
            p2p_client=p2p_client,
            progress_callback=progress_callback,
            required_peer_node_ids=[primary.node_id] if require_primary else None,
        )
        primary_locations = 0
        for chunk in initial.chunks:
            locations = [str(node_id) for node_id in chunk.get("locations", []) if str(node_id)]
            if primary.node_id in locations:
                primary_locations += 1
        info: dict[str, Any] = {
            "delegated": False,
            "primary_peer_id": primary.node_id,
            "primary_chunks": primary_locations,
            "candidate_peer_count": len(ranked),
        }
        if primary_locations <= 0:
            raise StorageError("Auslagerung zum ersten Peer ist fehlgeschlagen")

        remaining_peer_ids = [peer.node_id for peer in ranked[1:]]
        if remaining_peer_ids:
            delegation_manifest = _manifest_clone_with_chunks(
                manifest,
                initial.chunks,
                placement={
                    **dict(manifest.placement or {}),
                    "strategy": "delegated_peer_replication_source",
                    "delegation_primary_peer": primary.node_id,
                },
            )
            try:
                payload = p2p_client.post_replication_delegation(
                    primary,
                    manifest=delegation_manifest,
                    exclude_node_ids=[identity.node_id],
                )
                initial = _merge_peer_delegation_payload(initial, payload)
                info.update({
                    "delegated": True,
                    "delegated_peer_count": int(payload.get("peer_count") or 0),
                    "delegated_remote_successes": int(payload.get("remote_successes") or 0),
                    "delegated_remote_failures": int(payload.get("remote_failures") or 0),
                })
            except StorageError as exc:
                # Compatibility with peers that do not yet implement delegated
                # replication: keep the primary copy instead of falling back to
                # fan-out from the starter, because avoiding starter traffic is
                # the purpose of this path.
                info["delegation_error"] = str(exc)
        return initial, info

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
                    status="Upload ist abgeschlossen; Sicherheitskopien werden per Direct-/Gateway-Upload verteilt…",
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
            result, delegation_info = _replicate_via_primary_peer(
                manifest=manifest,
                peers=peers,
                progress_callback=_background_replication_progress(upload_id) if upload_id else None,
            )
            placement = dict(manifest.placement or {})
            placement.update({
                "strategy": "local_first_delegated_peer_replication",
                "delegated_replication": delegation_info,
                "target_count": len(result.targets),
                "targets": result.targets,
                "transfer_status": result.transfer_status,
                "remote_successes": result.remote_successes,
                "remote_failures": result.remote_failures,
                "local_chunks": result.local_chunks,
                "compressed_chunks": result.compressed_chunks,
                "raid_level": 1,
                "raid_mode": "dynamic_mirror",
                "desired_replicas": result.desired_replicas,
                "dynamic_mirror_cap": 4,
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
                        "Sicherheitskopie konnte über Direct-/Gateway-Peers noch nicht erstellt werden."
                    )
                else:
                    message = f"Upload abgeschlossen: {file_name or manifest.file_name}; keine direkt erreichbaren Speicher-Peers aktiv."
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
            active_peer_ids = set(peer_ids)
            base_desired_replicas = dynamic_mirror_replica_count(len(active_peers))
            for manifest in manifest_store.list_manifests():
                if manifest.owner_node_id != identity.node_id:
                    continue
                manifest_expects_local_copy = any(
                    identity.node_id in [str(node_id) for node_id in chunk.get("locations", [])]
                    for chunk in manifest.chunks
                )
                desired_replicas = base_desired_replicas
                if not manifest_expects_local_copy:
                    desired_replicas = max(1, min(base_desired_replicas, len(active_peers)))
                needs_replication = False
                for chunk in manifest.chunks:
                    digest = str(chunk.get("hash", ""))
                    existing_locations = [str(node_id) for node_id in chunk.get("locations", []) if str(node_id)]
                    healthy_locations = []
                    if identity.node_id in existing_locations and digest and chunk_store.chunk_path(digest).exists():
                        healthy_locations.append(identity.node_id)
                    healthy_locations.extend(node_id for node_id in existing_locations if node_id in active_peer_ids and node_id not in healthy_locations)
                    if len(healthy_locations) < desired_replicas:
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



    def _detect_lan_dashboard_urls() -> list[str]:
        """Return likely LAN dashboard URLs for the settings help card."""
        urls: list[str] = []
        seen: set[str] = set()
        port = int(getattr(config.web, "port", 8787) or 8787)

        def add_host(host: str) -> None:
            host = str(host or "").strip()
            if not host or host in {"0.0.0.0", "::"}:
                return
            try:
                ip_obj = ipaddress.ip_address(host)
            except ValueError:
                return
            if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast:
                return
            if ip_obj.version != 4:
                return
            if not (ip_obj.is_private or ip_obj.is_global):
                return
            url = f"http://{ip_obj}:{port}"
            if url not in seen:
                seen.add(url)
                urls.append(url)

        try:
            if psutil is not None:
                for addrs in psutil.net_if_addrs().values():
                    for addr in addrs:
                        if getattr(addr, "family", None) == socket.AF_INET:
                            add_host(getattr(addr, "address", ""))
        except Exception:
            pass

        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
                add_host(info[4][0])
        except Exception:
            pass

        if not urls:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.connect(("8.8.8.8", 80))
                    add_host(sock.getsockname()[0])
            except Exception:
                pass
        return urls[:8]

    def _configured_public_peer_urls() -> list[str]:
        """Return optional operator-configured public URLs for this node.

        The Direct-Peer build no longer uses a shared PHP relay.  When a node is
        reachable through DDNS/reverse proxy, administrators can still expose
        the address through environment variables so the one-sided peer exchange
        can give the remote node a reliable callback route.
        """
        candidates: list[str] = []
        raw_values = [
            os.environ.get("DCLOUD_PUBLIC_URL"),
            os.environ.get("DCLOUD_PUBLIC_URLS"),
            os.environ.get("DCLOUD_DIRECT_URL"),
            os.environ.get("DCLOUD_DIRECT_URLS"),
        ]
        for raw in raw_values:
            if not raw:
                continue
            for item in re.split(r"[\s,;]+", str(raw)):
                value = item.strip()
                if value:
                    candidates.append(value)
        return normalize_public_urls(candidates)

    def _local_peer_callback_urls(*, include_lan: bool = True) -> list[str]:
        urls: list[str] = []
        for url in _configured_public_peer_urls():
            if url not in urls:
                urls.append(url)
        if include_lan:
            for url in _detect_lan_dashboard_urls():
                try:
                    normalized = _normalize_direct_peer_url(url)
                except ValueError:
                    continue
                if normalized not in urls:
                    urls.append(normalized)
        return urls[:16]

    def _peer_exchange_payload() -> dict[str, Any]:
        stats = chunk_store.stats()
        return {
            "version": 1,
            "node_id": identity.node_id,
            "name": config.node.name,
            "display_name": display_name_for_peer(identity.node_id, config.node.name),
            "client_type": config.node.client_type,
            "web_port": int(getattr(config.web, "port", 8787) or 8787),
            "shared_storage_bytes": int(config.storage.limit_bytes),
            "free_storage_bytes": int(stats.free_limit_bytes),
            "accepts_peer_storage": True,
            "public_urls": _configured_public_peer_urls(),
            "callback_urls": _local_peer_callback_urls(),
            "lan_addresses": [url_parse.urlsplit(url).hostname for url in _detect_lan_dashboard_urls() if url_parse.urlsplit(url).hostname],
            "capabilities": {
                "direct_peer": True,
                "peer_exchange": True,
                "gateway_discovery": True,
                "gateway_proxy": True,
                "relay_removed": True,
            },
        }

    def _candidate_urls_from_peer_info(peer_info: dict[str, Any], *, fallback_endpoint: str = "", source_ip: str = "") -> list[str]:
        urls: list[str] = []

        def add(raw: Any) -> None:
            try:
                normalized = _normalize_direct_peer_url(raw)
            except ValueError:
                return
            if normalized not in urls:
                urls.append(normalized)

        for key in ("callback_urls", "public_urls", "urls"):
            raw = peer_info.get(key)
            values = raw if isinstance(raw, list) else ([raw] if raw else [])
            for value in values:
                add(value)
        if fallback_endpoint:
            add(fallback_endpoint)
        if source_ip:
            try:
                port = int(peer_info.get("web_port") or getattr(config.web, "port", 8787) or 8787)
            except Exception:
                port = int(getattr(config.web, "port", 8787) or 8787)
            host = str(source_ip or "").strip().strip("[]")
            if host:
                host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
                add(f"http://{host_part}:{port}")
        return urls[:16]

    def _store_direct_peer_from_info(
        peer_info: dict[str, Any],
        *,
        fallback_endpoint: str = "",
        source_ip: str = "",
        source: str = "peer_exchange",
        display_name: str | None = None,
    ) -> Peer | None:
        node_id = _safe_peer_id(str(peer_info.get("node_id") or ""))
        if not node_id or node_id == identity.node_id or node_id in _disabled_peer_ids():
            return None
        urls = _candidate_urls_from_peer_info(peer_info, fallback_endpoint=fallback_endpoint, source_ip=source_ip)
        if not urls:
            return None
        first = urls[0]
        try:
            parsed = url_parse.urlsplit(first)
            host = (parsed.hostname or "").strip().strip("[]")
            port = parsed.port or (443 if parsed.scheme == "https" else int(peer_info.get("web_port") or getattr(config.web, "port", 8787) or 8787))
        except Exception:
            return None
        if not host:
            return None
        now = time.time()
        label = (display_name or str(peer_info.get("display_name") or peer_info.get("name") or "") or display_name_for_peer(node_id)).strip()
        try:
            shared_storage_bytes = int(peer_info.get("shared_storage_bytes") or 0)
        except Exception:
            shared_storage_bytes = 0
        try:
            free_storage_bytes = int(peer_info.get("free_storage_bytes") or shared_storage_bytes or 0)
        except Exception:
            free_storage_bytes = shared_storage_bytes
        accepts_peer_storage = bool(peer_info.get("accepts_peer_storage", True))
        with manual_peer_routes_lock:
            existing = manual_peer_routes.get(node_id, {})
            existing_urls = [str(url) for url in existing.get("urls", []) if str(url)] if isinstance(existing.get("urls"), list) else []
            merged_urls = []
            for url in [*urls, *existing_urls]:
                if url not in merged_urls:
                    merged_urls.append(url)
            manual_peer_routes[node_id] = {
                "node_id": node_id,
                "display_name": label,
                "urls": merged_urls[:16],
                "created_at": float(existing.get("created_at") or now),
                "updated_at": now,
                "last_ok_at": now,
                "last_error": "",
                "source": source,
                "client_type": str(peer_info.get("client_type") or "server"),
                "accepts_peer_storage": accepts_peer_storage,
                "shared_storage_bytes": shared_storage_bytes,
                "free_storage_bytes": free_storage_bytes,
                "via_gateway_node_id": str(existing.get("via_gateway_node_id") or ""),
                "gateway_display_name": str(existing.get("gateway_display_name") or ""),
            }
            _persist_manual_peer_routes()
            stored_route = dict(manual_peer_routes[node_id])
        routed_peer = _manual_route_to_peer(stored_route)
        if routed_peer is not None:
            peer_provider.add_or_update(routed_peer)
            return routed_peer
        return None

    def _ingest_peer_exchange_response(payload: dict[str, Any], gateway_peer: Peer | None = None) -> int:
        count = 0
        remote_peer = payload.get("peer") if isinstance(payload.get("peer"), dict) else None
        if remote_peer is not None:
            stored = _store_direct_peer_from_info(remote_peer, source="peer_exchange")
            if stored is not None:
                count += 1
        raw_peers = payload.get("peers") if isinstance(payload.get("peers"), list) else []
        if gateway_peer is not None:
            for item in raw_peers:
                if isinstance(item, dict) and _store_gateway_peer_route(gateway_peer, item):
                    count += 1
        else:
            for item in raw_peers:
                if isinstance(item, dict):
                    stored = _store_direct_peer_from_info(item, source="peer_exchange")
                    if stored is not None:
                        count += 1
        return count

    def _perform_peer_exchange(peer: Peer, *, force: bool = False) -> int:
        """Run the active one-sided Direct-Peer handshake with a reachable peer."""
        _ = force
        payload = _peer_exchange_payload()
        response = p2p_client.post_peer_connect(peer, payload)
        count = _ingest_peer_exchange_response(response, gateway_peer=peer)
        try:
            count += _sync_gateway_peers_from_peer(peer, force=force)
        except Exception:
            LOG.debug("Gateway discovery after peer exchange failed for %s", peer.node_id, exc_info=True)
        return count

    try:
        _refresh_manual_peer_routes(force=True)
    except Exception:
        LOG.debug("Initial Direct-Peer route refresh failed", exc_info=True)

    def settings_payload(stats: StorageStats | None = None, peers: list[Any] | None = None) -> dict[str, Any]:
        current_stats = stats or chunk_store.stats()
        current_peers = peers if peers is not None else _list_active_peers()
        capacity = _network_storage_capacity(current_stats, current_peers)
        smb_server = app.config.get("DCLOUD_SMB_SERVER")
        smb_runtime_status = app.config.get("DCLOUD_SMB_STATUS") or {}
        runtime_smb_running = bool(smb_runtime_status.get("running", getattr(smb_server, "running", False)))
        runtime_smb_port = int(smb_runtime_status.get("port", getattr(smb_server, "actual_port", config.smb.port)) or config.smb.port)
        runtime_smb_error = str(smb_runtime_status.get("last_error", getattr(smb_server, "last_error", "")) or "")
        smb_root_path = str(app.config.get("DCLOUD_SMB_ROOT") or config.storage.path)
        if config.smb.enabled and not runtime_smb_running and not runtime_smb_error:
            runtime_smb_error = (
                "SMB-Server läuft nicht. Der Dienst wird normalerweise automatisch neu gestartet; prüfe sonst Logausgabe, Port-Freigabe und ob der Speicherpfad verfügbar ist."
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
            "fixedRelayUrl": "",
            "fixedRelayUrls": [],
            "fixedRelayUrlsText": "",
            "relayUrl": "",
            "relayUrls": [],
            "additionalRelayUrls": [],
            "additionalRelayUrlsText": "",
            "relayEnabled": False,
            "relaySecret": "",
            "relaySecretSet": False,
            "relayTokenMode": "removed",
            "relayTokenLabel": "Entfernt",
            "directConnectionModeLabel": "Nur Direktverbindung / Gateway",
            "allowRelayDataTransfer": False,
            "dashboardTcpPort": int(getattr(config.web, "port", 8787) or 8787),
            "p2pApiTcpPort": int(getattr(config.web, "port", 8787) or 8787),
            "discoveryUdpPort": int(getattr(config.network, "udp_port", 6881) or 6881),
            "discoveryUdpPorts": list(getattr(config.network, "auto_discovery_ports", [6881]) or [int(getattr(config.network, "udp_port", 6881) or 6881)]),
            "lanDashboardUrls": _detect_lan_dashboard_urls(),
            "reverseProxyPublicPort": 443,
            "directFirewallSummary": f"TCP {int(getattr(config.web, 'port', 8787) or 8787)} freigeben; UDP {int(getattr(config.network, 'udp_port', 6881) or 6881)} nur fuer LAN-Erkennung; optional HTTPS 443 per Reverse Proxy",
            "chatEnabled": _chat_enabled(),
            "chatAlias": _chat_alias(),
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
        return []

    def _relay_statuses() -> list[dict[str, Any]]:
        return []

    def _relay_overall_status(statuses: list[dict[str, Any]]) -> tuple[str, str | None]:
        return "entfernt", None

    def recovery_payload(*, include_secret: bool | None = None) -> dict[str, Any]:
        show_secret = _current_user_is_admin() if include_secret is None else bool(include_secret)
        payload = {
            "nodeId": identity.node_id,
            "nodeIdShort": identity.node_id[:12],
            "backupToken": "",
            "retentionDays": int(REMOTE_DELETE_GRACE_SECONDS / 86400),
            "identityPath": str(config.node.identity_path),
            "adminOnly": True,
        }
        if show_secret:
            payload["backupToken"] = build_backup_token(identity)
        return payload

    def _backup_token_download_payload() -> dict[str, Any]:
        return {
            "kind": "dcloud-backup-token",
            "version": 1,
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "nodeId": identity.node_id,
            "nodeIdShort": identity.node_id[:12],
            "backupToken": build_backup_token(identity),
            "retentionDays": int(REMOTE_DELETE_GRACE_SECONDS / 86400),
            "warning": "Geheim halten. Wer diesen Token besitzt, kann diese dcloud-Node-ID wiederherstellen.",
        }

    def _extract_backup_token_from_upload(raw: bytes) -> str:
        if len(raw) > 256 * 1024:
            raise ValueError("Backup-Token-Datei ist zu groß")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("Backup-Token-Datei ist keine lesbare Text-/JSON-Datei") from exc
        stripped = text.strip()
        if not stripped:
            raise ValueError("Backup-Token-Datei ist leer")
        if stripped.startswith("{"):
            try:
                doc = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError("Backup-Token-Datei enthält kein gültiges JSON") from exc
            for key in ("backupToken", "backup_token", "token"):
                token = str(doc.get(key) or "").strip()
                if token:
                    return token
            raise ValueError("Backup-Token-Datei enthält kein Feld backupToken")
        match = re.search(r"DCLOUD-BACKUP-v1:[A-Za-z0-9]{6,64}:[A-Za-z0-9_-]+:[A-Fa-f0-9]{16}", stripped)
        if match:
            return match.group(0)
        return stripped

    def _import_backup_token_and_restart(token: str) -> dict[str, Any]:
        recovered = IdentityManager(config.node.identity_path).import_backup_token(token)
        message = (
            f"Backup-Token übernommen. Node-ID nach Neustart: {recovered.node_id[:12]}. "
            "Der Service wird jetzt neu gestartet; danach 'Wiederherstellung von Peers starten' verwenden."
        )
        _restart_current_process_delayed()
        return {"ok": True, "message": message, "nodeId": recovered.node_id, "restart": True}

    def _sync_incoming_shared_manifests_from_peers(
        peers: list[Any] | None = None,
        *,
        min_interval_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Pull shared manifests from active peers so remote shares are not push-only.

        A share click on the owner node tries to push the signed manifest to the
        selected peer.  That can still fail when the target is remote, wakes up
        later, or is only reachable through the relay mailbox.  This receiver-side
        refresher asks visible peers for manifests owned by that peer and imports
        only those whose signed access section allows this local node.  The file
        chunks are not transferred here; downloads still use LAN/Public/Gateway
        and relay fallback.
        """
        active_peers = [peer for peer in (peers if peers is not None else _list_active_peers()) if peer.node_id != identity.node_id]
        if not active_peers:
            return {"scanned": 0, "imported": 0, "already_present": 0, "failed": 0, "skipped": 0}

        now = time.time()
        interval = max(10, int(min_interval_seconds or INCOMING_SHARE_SYNC_SECONDS))
        max_peers = max(1, int(INCOMING_SHARE_SYNC_MAX_PEERS_PER_PASS))
        scanned = 0
        imported = 0
        already_present = 0
        failed = 0
        skipped = 0

        for peer in active_peers:
            peer_node_id = str(getattr(peer, "node_id", "") or "")
            if not peer_node_id:
                skipped += 1
                continue
            last_attempt = incoming_share_sync_attempts.get(peer_node_id, 0.0)
            if last_attempt and now - last_attempt < interval:
                skipped += 1
                continue
            if scanned >= max_peers:
                skipped += 1
                continue
            incoming_share_sync_attempts[peer_node_id] = now
            scanned += 1
            try:
                try:
                    raw_manifests = p2p_client.get_shared_manifests(peer)
                except Exception:
                    # Older peers may not yet expose /api/p2p/manifests/shared.
                    # Fall back to the owner-specific endpoint so mixed-version
                    # meshes still learn newly shared files from the owner peer.
                    raw_manifests = p2p_client.get_manifests_for_owner(peer, peer_node_id)
            except Exception:
                failed += 1
                LOG.debug("Incoming share manifest pull from peer %s failed", peer_node_id, exc_info=True)
                continue
            for raw_manifest in raw_manifests:
                try:
                    manifest = FileManifest.from_dict(raw_manifest)
                    if manifest.owner_node_id == identity.node_id:
                        continue
                    if not manifest_store.may_access(manifest, identity.node_id):
                        continue
                    if manifest_store.is_share_revoked(manifest.manifest_id, manifest.owner_node_id):
                        continue
                    if manifest_store.is_file_deleted(manifest.manifest_id, manifest.owner_node_id):
                        continue
                    try:
                        manifest_store.load(manifest.manifest_id)
                        already_present += 1
                        continue
                    except StorageError:
                        pass
                    manifest_store.save_imported(manifest)
                    imported += 1
                except Exception:
                    failed += 1
                    LOG.debug("Incoming shared manifest import from peer %s failed", peer_node_id, exc_info=True)

        if imported:
            _sync_peer_connector_settings()
        if len(incoming_share_sync_attempts) > 2000:
            cutoff = now - max(interval * 4, 3600)
            for key, ts in list(incoming_share_sync_attempts.items()):
                if ts < cutoff:
                    incoming_share_sync_attempts.pop(key, None)
        return {
            "scanned": scanned,
            "imported": imported,
            "already_present": already_present,
            "failed": failed,
            "skipped": skipped,
        }

    def _recover_owned_manifests_from_peers(peers: list[Any] | None = None) -> dict[str, Any]:
        active_peers = peers if peers is not None else _list_active_peers()
        imported = 0
        already_present = 0
        failed = 0
        scanned = 0
        messages: list[str] = []
        for peer in active_peers:
            scanned += 1
            try:
                raw_manifests = p2p_client.get_manifests_for_owner(peer, identity.node_id)
            except Exception as exc:
                failed += 1
                messages.append(f"{display_name_for_peer(getattr(peer, 'node_id', ''), getattr(peer, 'name', None))}: {exc}")
                continue
            for raw_manifest in raw_manifests:
                try:
                    manifest = FileManifest.from_dict(raw_manifest)
                    if manifest.owner_node_id != identity.node_id:
                        continue
                    try:
                        manifest_store.load(manifest.manifest_id)
                        already_present += 1
                        continue
                    except StorageError:
                        pass
                    manifest_store.save_imported(manifest)
                    imported += 1
                except Exception as exc:
                    failed += 1
                    messages.append(f"Manifest von {getattr(peer, 'node_id', '')[:12]} konnte nicht importiert werden: {exc}")
        if imported:
            _sync_peer_connector_settings()
        return {
            "scannedPeers": scanned,
            "imported": imported,
            "alreadyPresent": already_present,
            "failed": failed,
            "messages": messages[:8],
        }

    def network_payload() -> dict[str, Any]:
        relay_statuses = _relay_statuses()
        relay_status, relay_error = _relay_overall_status(relay_statuses)
        return {
            "webHost": config.web.host,
            "webPort": config.web.port,
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
            "fixedRelayUrl": "",
            "fixedRelayUrls": [],
            "fixedRelayUrlsText": "",
            "relayUrl": "",
            "relayUrls": [],
            "additionalRelayUrls": [],
            "relayEnabled": False,
            "relayPollIntervalSeconds": 0,
            "relayRequestTimeoutSeconds": 0,
            "relayStatus": "entfernt",
            "relayLastError": None,
            "relayStatuses": [],
            "relayTokenMode": "removed",
            "allowRelayDataTransfer": False,
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
                "chat_enabled": _chat_enabled(),
                "chat_alias": _chat_alias(),
            }.items():
                if hasattr(connector, name):
                    setattr(connector, name, value)


    def _stream_external_download_to_relay(local_token: str, stream_id: str, relay_client: HttpRelayClient) -> RelayHttpResponse:
        return RelayHttpResponse(410, {"Content-Type": "application/json"}, b'{"ok":false,"message":"Direct-Peer-Build: indirekter Server-Datenweg entfernt"}')

    def _dispatch_relay_request(envelope: dict[str, Any]) -> RelayHttpResponse:
        return RelayHttpResponse(410, {"Content-Type": "application/json"}, b'{"ok":false,"message":"Direct-Peer-Build: indirekter Server-Datenweg entfernt"}')

    def _stop_relay_transport() -> None:
        with relay_lock:
            for transport in list(relay_transports.values()):
                stop = getattr(transport, "stop", None)
                if callable(stop):
                    stop()
            relay_transports.clear()
            relay_clients.clear()
            p2p_client.clear_relay_clients()
            app.config["DCLOUD_RELAY_TRANSPORT"] = None
            app.config["DCLOUD_RELAY_TRANSPORTS"] = {}

    def _learn_relay_urls(urls: list[str]) -> None:
        return

    def _relay_inventory_payload() -> dict[str, Any]:
        """Return local chunk availability for direct-peer status/debug payloads.

        The relay remains a lightweight tracker/signaling service.  It does not
        carry bulk data, but it can tell other clients which online peer recently
        announced local copies for a manifest.  The payload is deliberately
        bounded because it is sent with regular relay heartbeats.
        """
        manifests_payload: list[dict[str, Any]] = []
        max_manifests = 200
        max_total_chunks = 4096
        total_chunks = 0
        try:
            visible = manifest_store.list_visible_for_node(identity.node_id)
        except Exception:
            visible = []
        for manifest in visible:
            chunk_hashes: list[str] = []
            for chunk in manifest.chunks:
                digest = str(chunk.get("hash") or "").strip()
                if not digest or not chunk_store.chunk_path(digest).exists():
                    continue
                chunk_hashes.append(digest)
                total_chunks += 1
                if len(chunk_hashes) >= 512 or total_chunks >= max_total_chunks:
                    break
            if chunk_hashes:
                manifests_payload.append({
                    "manifest_id": manifest.manifest_id,
                    "chunk_hashes": chunk_hashes,
                    "chunk_count": len(chunk_hashes),
                    "complete": len(chunk_hashes) >= len(manifest.chunks),
                })
            if len(manifests_payload) >= max_manifests or total_chunks >= max_total_chunks:
                break
        return {"version": 1, "updated_at": int(time.time()), "manifests": manifests_payload}

    def _configure_relay_transport() -> None:
        with relay_lock:
            for transport in list(relay_transports.values()):
                stop = getattr(transport, "stop", None)
                if callable(stop):
                    stop()
            relay_transports.clear()
            relay_clients.clear()
            p2p_client.clear_relay_clients()
            app.config["DCLOUD_RELAY_TRANSPORTS"] = {}
            app.config["DCLOUD_RELAY_TRANSPORT"] = None
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

    def _deliver_active_manifest_shares(peers: list[Any] | None = None, *, min_interval_seconds: int | None = None) -> dict[str, int]:
        """Best-effort sync for peer shares when recipients appear later via Internet.

        The interactive share action sends the manifest to peers that are active at
        that moment. Remote peers can be offline, behind NAT, or only visible a
        few relay polling cycles later. This refresher treats the PHP relay as a
        tracker/signaling channel and periodically re-pushes still-shared owned
        manifests to currently active authorized peers. The chunks themselves
        remain fetched via direct LAN/Public/Gateway routes first.
        """
        active_peers = [peer for peer in (peers if peers is not None else _list_active_peers()) if peer.node_id != identity.node_id]
        if not active_peers:
            return {"eligible": 0, "delivered": 0, "failed": 0, "skipped": 0}

        now = time.time()
        retry_seconds = max(10, int(min_interval_seconds or SHARE_DELIVERY_RETRY_SECONDS))
        success_refresh_seconds = max(retry_seconds, int(SHARE_DELIVERY_SUCCESS_REFRESH_SECONDS))
        max_per_pass = max(1, int(SHARE_DELIVERY_MAX_PER_PASS))
        eligible = 0
        delivered = 0
        failed = 0
        skipped = 0
        sent_this_pass = 0

        owned_shared: list[FileManifest] = []
        for manifest in manifest_store.list_manifests():
            if manifest.owner_node_id != identity.node_id:
                continue
            access = manifest.access or {}
            if access.get("visibility") not in {"shared", "public"}:
                continue
            if manifest_store.is_file_deleted(manifest.manifest_id, manifest.owner_node_id):
                continue
            owned_shared.append(manifest)

        for manifest in owned_shared:
            access = manifest.access or {}
            shared_with = {str(item) for item in access.get("shared_with", []) if str(item)}
            wildcard = access.get("visibility") == "public" or "*" in shared_with or not shared_with
            for peer in active_peers:
                if not wildcard and peer.node_id not in shared_with:
                    continue
                eligible += 1
                key = f"{manifest.manifest_id}:{manifest.signature}:{peer.node_id}"
                last_attempt = share_delivery_attempts.get(key, 0.0)
                # Successful deliveries are refreshed occasionally so a restarted
                # remote peer can recover a shared manifest without the owner having
                # to toggle the share again. Failed attempts retry much sooner.
                cooldown = success_refresh_seconds if last_attempt > 0 else retry_seconds
                if last_attempt and now - last_attempt < cooldown:
                    skipped += 1
                    continue
                if sent_this_pass >= max_per_pass:
                    skipped += 1
                    continue

                result = p2p_client.post_manifest(peer, manifest)
                sent_this_pass += 1
                if result.ok:
                    delivered += 1
                    share_delivery_attempts[key] = now
                else:
                    failed += 1
                    # Retry failures on the shorter retry interval.
                    share_delivery_attempts[key] = now - max(0, success_refresh_seconds - retry_seconds)

        # Keep the in-memory throttle bounded; old manifest ids naturally become
        # irrelevant after toggles, deletes or file updates.
        if len(share_delivery_attempts) > 5000:
            cutoff = now - max(success_refresh_seconds * 2, 3600)
            for key, ts in list(share_delivery_attempts.items()):
                if ts < cutoff:
                    share_delivery_attempts.pop(key, None)
        return {"eligible": eligible, "delivered": delivered, "failed": failed, "skipped": skipped}

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

    def _ensure_file_deletion_delivery_worker() -> None:
        """Start the asynchronous peer-delete delivery worker once."""
        nonlocal file_deletion_delivery_worker_started
        with file_deletion_delivery_lock:
            if file_deletion_delivery_worker_started:
                return
            file_deletion_delivery_worker_started = True
        worker = threading.Thread(
            target=_file_deletion_delivery_worker_loop,
            name="dcloud-file-delete-delivery",
            daemon=True,
        )
        worker.start()

    def _request_file_deletion_delivery(*, min_interval_seconds: float = 0.0) -> bool:
        """Ask the background worker to deliver pending delete tombstones.

        File deletion in the dashboard must stay immediate: the local manifest is
        removed in the request thread, while remote peers are notified later by
        this worker.  The interval guard prevents the normal dashboard refresh
        loop from contacting every peer on every poll.
        """
        nonlocal last_file_deletion_delivery_enqueue_at
        now = time.monotonic()
        with file_deletion_delivery_lock:
            if min_interval_seconds > 0 and now - last_file_deletion_delivery_enqueue_at < min_interval_seconds:
                return False
            last_file_deletion_delivery_enqueue_at = now
            file_deletion_delivery_event.set()
        _ensure_file_deletion_delivery_worker()
        return True

    def _file_deletion_delivery_worker_loop() -> None:
        while True:
            file_deletion_delivery_event.wait()
            with file_deletion_delivery_lock:
                file_deletion_delivery_event.clear()
            try:
                _deliver_pending_file_deletions()
            except Exception:
                # Best-effort background cleanup must never kill the dashboard.
                pass

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
        """Delete an owned manifest locally and queue remote peer cleanup.

        The dashboard should not wait until every storage peer confirms a delete.
        The local manifest is removed immediately so the file disappears from the
        UI, and the signed deletion tombstone is delivered asynchronously.
        """
        if manifest.owner_node_id != identity.node_id:
            raise StorageError("Only the owner can delete this manifest")
        target_node_ids = _manifest_delete_target_node_ids(manifest)
        if target_node_ids:
            deletion = build_manifest_deletion(manifest, identity)
            manifest_store.add_file_deletion(deletion, target_node_ids)
            _request_file_deletion_delivery()
        manifest_store.delete(manifest.manifest_id)
        _sync_peer_connector_settings()
        return {
            "target_count": len(target_node_ids),
            "delivered": 0,
            "failed": 0,
            "queued": len(target_node_ids),
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
            "display_folder_path": display_folder_for_node(manifest, identity.node_id),
            "incoming_share": manifest.owner_node_id != identity.node_id,
            "owner_node_id": manifest.owner_node_id,
            "created_at": manifest.created_at,
            "access": manifest.access or {"visibility": "private", "shared_with": []},
            "placement": manifest.placement or {},
            "storage_locations": locations,
            "remote_storage_count": len([node_id for node_id in locations if node_id != identity.node_id]),
            "download_url": url_for("download", manifest_id=manifest.manifest_id),
            "preview_url": url_for("preview_file", manifest_id=manifest.manifest_id),
            "sheet_preview_url": url_for("preview_sheet", manifest_id=manifest.manifest_id),
            "external_link_url": url_for("api_create_external_download_link", manifest_id=manifest.manifest_id),
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
        if share_delivery_lock.acquire(blocking=False):
            try:
                _deliver_active_manifest_shares(peers)
            finally:
                share_delivery_lock.release()
        if incoming_share_sync_lock.acquire(blocking=False):
            try:
                _sync_incoming_shared_manifests_from_peers(peers)
            finally:
                incoming_share_sync_lock.release()
        _request_file_deletion_delivery(min_interval_seconds=8.0)
        manifest_store.purge_expired_remote_chunk_deletions()
        manifests = manifest_store.list_visible_for_node(identity.node_id)
        folders = manifest_store.list_folders_for_node(identity.node_id)
        tree = build_folder_tree(manifests, folders, identity.node_id)
        return {
            "stateVersion": time.time_ns(),
            "nodeId": identity.node_id,
            "stats": stats_payload(stats),
            "settings": settings_payload(stats, peers),
            "network": network_payload(),
            "networkLoad": network_load_sampler.sample(peer_count=len(peers)),
            "networkCapacity": _network_storage_capacity(stats, peers),
            "webHosting": web_hosting_payload(peers),
            "recovery": recovery_payload(),
            "webFiles": web_files_payload(),
            "browserDownloads": browser_downloads_payload(),
            "peers": [peer.to_dict() for peer in peers],
            "disabledPeers": _disabled_peers_payload(),
            "manualPeerRoutes": _manual_peer_routes_payload(),
            "fileCount": len(manifests),
            "folders": folders,
            "folderTree": folder_tree_json(tree),
            "gitRevision": current_git_revision(),
            "auth": _auth_payload(),
        }

    @app.route("/setup", methods=["GET", "POST"])
    def setup() -> Response | str:
        if user_store.has_users():
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "admin")
            password = request.form.get("password", "")
            password_repeat = request.form.get("password_repeat", "")
            try:
                if password != password_repeat:
                    raise ValueError("Passwörter stimmen nicht überein")
                user = user_store.create_user(username, password, role="admin", enabled=True)
                session.clear()
                session["dcloud_username"] = user.username
                session["dcloud_role"] = user.role
                session.permanent = True
                flash("Admin-Benutzer erstellt. Willkommen im dcloud Dashboard.", "success")
                return redirect(url_for("dashboard"))
            except ValueError as exc:
                flash(str(exc), "error")
        return render_template("setup.html", node_name=config.node.name)

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Response | str:
        if not user_store.has_users():
            return redirect(url_for("setup"))
        next_url = _safe_next(request.values.get("next"), url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            user = user_store.verify(username, password)
            if user is None:
                message = "Benutzername oder Passwort ist falsch"
                if _is_ajax_request():
                    return jsonify({"ok": False, "message": message}), 401
                flash(message, "error")
            else:
                session.clear()
                session["dcloud_username"] = user.username
                session["dcloud_role"] = user.role
                session.permanent = True
                if _is_ajax_request():
                    return jsonify({"ok": True, "message": "Angemeldet", "next": next_url, "auth": _auth_payload()})
                return redirect(next_url)
        return render_template("login.html", node_name=config.node.name, next_url=next_url)

    @app.post("/logout")
    def logout() -> Response:
        session.clear()
        if _is_ajax_request():
            return jsonify({"ok": True, "message": "Abgemeldet"})
        return redirect(url_for("login"))

    @app.post("/api/system/restart")
    def api_system_restart() -> Response:
        admin_error = _require_admin()
        if admin_error is not None:
            return admin_error
        _restart_current_process_delayed()
        return jsonify({"ok": True, "message": "Service-Neustart wurde ausgelöst"})

    @app.get("/api/recovery")
    def api_recovery() -> Response:
        admin_error = _require_admin()
        if admin_error is not None:
            return admin_error
        return jsonify({"ok": True, "recovery": recovery_payload()})

    @app.get("/api/recovery/token/download")
    def api_recovery_token_download() -> Response:
        admin_error = _require_admin()
        if admin_error is not None:
            return admin_error
        payload = _backup_token_download_payload()
        raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"dcloud-backup-token-{identity.node_id[:12]}-{stamp}.json"
        response = send_file(
            BytesIO(raw),
            mimetype="application/json; charset=utf-8",
            as_attachment=True,
            download_name=filename,
            max_age=0,
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    @app.post("/api/recovery/import")
    def api_recovery_import() -> Response:
        admin_error = _require_admin()
        if admin_error is not None:
            return admin_error
        data = request.get_json(silent=True) or request.form
        token = str(data.get("backup_token") or data.get("token") or "").strip()
        try:
            return jsonify(_import_backup_token_and_restart(token))
        except ValueError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400
        except OSError as exc:
            return jsonify({"ok": False, "message": f"Identität konnte nicht geschrieben werden: {exc}"}), 500

    @app.post("/api/recovery/import-file")
    def api_recovery_import_file() -> Response:
        admin_error = _require_admin()
        if admin_error is not None:
            return admin_error
        upload = request.files.get("backup_token_file") or request.files.get("file")
        if upload is None or not upload.filename:
            return jsonify({"ok": False, "message": "Bitte eine Backup-Token-Datei auswählen"}), 400
        try:
            token = _extract_backup_token_from_upload(upload.read())
            return jsonify(_import_backup_token_and_restart(token))
        except ValueError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400
        except OSError as exc:
            return jsonify({"ok": False, "message": f"Identität konnte nicht geschrieben werden: {exc}"}), 500

    @app.post("/api/recovery/scan")
    def api_recovery_scan() -> Response:
        admin_error = _require_admin()
        if admin_error is not None:
            return admin_error
        result = _recover_owned_manifests_from_peers()
        message = (
            f"Wiederherstellung geprüft: {result['imported']} Datei-Manifest(e) importiert, "
            f"{result['alreadyPresent']} bereits vorhanden, {result['failed']} Fehler."
        )
        return jsonify({"ok": True, "message": message, "result": result, "state": state_payload()})

    @app.get("/api/users")
    def api_users() -> Response:
        admin_error = _require_admin()
        if admin_error is not None:
            return admin_error
        return jsonify({"ok": True, "users": user_store.list_users(), "currentUser": _current_user()})

    @app.post("/api/users")
    def api_users_create() -> Response:
        admin_error = _require_admin()
        if admin_error is not None:
            return admin_error
        data = request.get_json(silent=True) or request.form
        try:
            user = user_store.create_user(
                str(data.get("username") or ""),
                str(data.get("password") or ""),
                role=str(data.get("role") or "user"),
                enabled=bool(data.get("enabled", True)),
            )
            return jsonify({"ok": True, "message": f"Benutzer erstellt: {user.username}", "user": user.to_public_dict(), "users": user_store.list_users()})
        except ValueError as exc:
            return jsonify({"ok": False, "message": str(exc), "users": user_store.list_users()}), 400

    @app.post("/api/users/<username>")
    def api_users_update(username: str) -> Response:
        admin_error = _require_admin()
        if admin_error is not None:
            return admin_error
        data = request.get_json(silent=True) or request.form
        current = _current_username()
        try:
            role = data.get("role") if "role" in data else None
            enabled = data.get("enabled") if "enabled" in data else None
            if isinstance(enabled, str):
                enabled = enabled.lower() in {"1", "true", "yes", "on", "aktiv"}
            password = str(data.get("password") or "") if "password" in data else None
            if username == current and enabled is False:
                raise ValueError("Du kannst deinen eigenen Benutzer nicht deaktivieren")
            if username == current and role is not None and str(role).lower() != "admin" and user_store.count_admins(exclude_username=username) <= 0:
                raise ValueError("Der letzte aktive Administrator darf nicht herabgestuft werden")
            existing = user_store.get(username)
            if existing and existing.role == "admin" and enabled is False and user_store.count_admins(exclude_username=username) <= 0:
                raise ValueError("Der letzte aktive Administrator darf nicht deaktiviert werden")
            user = user_store.update_user(username, role=role, enabled=enabled, password=password or None)
            return jsonify({"ok": True, "message": f"Benutzer aktualisiert: {user.username}", "user": user.to_public_dict(), "users": user_store.list_users()})
        except ValueError as exc:
            return jsonify({"ok": False, "message": str(exc), "users": user_store.list_users()}), 400

    @app.delete("/api/users/<username>")
    def api_users_delete(username: str) -> Response:
        admin_error = _require_admin()
        if admin_error is not None:
            return admin_error
        current = _current_username()
        try:
            if username == current:
                raise ValueError("Du kannst deinen eigenen Benutzer nicht löschen")
            existing = user_store.get(username)
            if existing and existing.role == "admin" and user_store.count_admins(exclude_username=username) <= 0:
                raise ValueError("Der letzte aktive Administrator darf nicht gelöscht werden")
            user_store.delete_user(username)
            return jsonify({"ok": True, "message": f"Benutzer gelöscht: {username}", "users": user_store.list_users()})
        except ValueError as exc:
            return jsonify({"ok": False, "message": str(exc), "users": user_store.list_users()}), 400

    @app.get("/")
    def dashboard() -> str:
        stats = chunk_store.stats()
        peers = _list_active_peers()
        if incoming_share_sync_lock.acquire(blocking=False):
            try:
                _sync_incoming_shared_manifests_from_peers(peers, min_interval_seconds=10)
            finally:
                incoming_share_sync_lock.release()
        manifests = manifest_store.list_visible_for_node(identity.node_id)
        folders = manifest_store.list_folders_for_node(identity.node_id)
        tree = build_folder_tree(manifests, folders, identity.node_id)
        return render_template(
            "dashboard.html",
            config=config,
            identity=identity,
            stats=stats,
            stats_json=stats_payload(stats),
            peers=peers,
            peers_json=[peer.to_dict() for peer in peers],
            disabled_peers_json=_disabled_peers_payload(),
            settings_json=settings_payload(stats, peers),
            network_json=network_payload(),
            network_load_json=network_load_sampler.sample(peer_count=len(peers)),
            web_hosting_json=web_hosting_payload(peers),
            recovery_json=recovery_payload(),
            web_files_json=web_files_payload(),
            browser_downloads_json=browser_downloads_payload(),
            manifests=manifests,
            folder_tree=tree,
            folder_tree_json=folder_tree_json(tree),
            folders=folders,
            default_folder=DEFAULT_FOLDER,
            shared_folder=INCOMING_SHARES_FOLDER,
            git_revision=current_git_revision(),
            auth=_auth_payload(),
            current_user=_current_user(),
            large_upload_threshold_bytes=LARGE_UPLOAD_THRESHOLD_BYTES,
            large_upload_chunk_bytes=LARGE_UPLOAD_CHUNK_BYTES,
        )

    @app.get("/files")
    def files() -> str:
        peers = _list_active_peers()
        if incoming_share_sync_lock.acquire(blocking=False):
            try:
                _sync_incoming_shared_manifests_from_peers(peers, min_interval_seconds=10)
            finally:
                incoming_share_sync_lock.release()
        manifests = manifest_store.list_visible_for_node(identity.node_id)
        folders = manifest_store.list_folders_for_node(identity.node_id)
        return render_template(
            "files.html",
            manifests=manifests,
            folder_tree=build_folder_tree(manifests, folders, identity.node_id),
            folders=folders,
            identity=identity,
            default_folder=DEFAULT_FOLDER,
            shared_folder=INCOMING_SHARES_FOLDER,
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

    @app.route("/dcloud-site", defaults={"path": ""}, methods=["GET", "POST", "HEAD"], strict_slashes=False)
    @app.route("/dcloud-site/<path:path>", methods=["GET", "POST", "HEAD"], strict_slashes=False)
    def dcloud_site(path: str = "") -> Response:
        try:
            return _serve_local_web_path(path or "/")
        except Exception as exc:
            return Response(
                f"dcloud Webspace-Route fehlgeschlagen: {type(exc).__name__}: {exc}",
                status=500,
                content_type="text/plain; charset=utf-8",
            )

    @app.get("/api/browser/hosts")
    def api_browser_hosts() -> Response:
        peers = _list_active_peers()
        return jsonify({"ok": True, "webHosting": web_hosting_payload(peers)})


    def _browser_target_url_from_request() -> str:
        target_url = _browser_url(request.args.get("url"))
        if request.method.upper() == "GET":
            passthrough: list[tuple[str, str]] = []
            reserved = {"url", "browser_token", "native", "browser_download"}
            for key in request.args.keys():
                if key in reserved:
                    continue
                for value in request.args.getlist(key):
                    passthrough.append((key, value))
            if passthrough:
                parsed_target = url_parse.urlsplit(target_url)
                merged_query = url_parse.urlencode(
                    url_parse.parse_qsl(parsed_target.query, keep_blank_values=True) + passthrough,
                    doseq=True,
                )
                target_url = url_parse.urlunsplit((
                    parsed_target.scheme,
                    parsed_target.netloc,
                    parsed_target.path,
                    merged_query,
                    parsed_target.fragment,
                ))
        return target_url

    @app.get("/browser/search")
    def browser_search() -> Response:
        query = str(request.args.get("q") or "").strip()
        if not query:
            return redirect(_browser_proxy_url_for("https://duckduckgo.com/html/"), code=302)
        return redirect(_browser_proxy_url_for(_safe_search_url(query)), code=302)

    @app.route("/browser/view", methods=["GET", "POST", "HEAD", "OPTIONS"])
    def browser_view() -> Response:
        if request.method == "OPTIONS":
            response = Response("", status=204)
            response.headers["Access-Control-Allow-Origin"] = "null"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, HEAD, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Accept"
            response.headers["Access-Control-Allow-Credentials"] = "true"
            return response
        target_url = _browser_target_url_from_request()
        parsed = url_parse.urlsplit(target_url)
        hostname = (parsed.hostname or "").lower()
        native_mode = str(request.args.get("native") or "").lower() in {"1", "true", "yes"}
        try:
            if hostname.endswith(".dcloud"):
                return _fetch_dcloud_browser_url(target_url, native_mode=native_mode)
            return _fetch_external_browser_url(target_url, native_mode=native_mode)
        except Exception as exc:
            return Response(
                f"dcloud Browser konnte die Seite nicht laden: {type(exc).__name__}: {exc}",
                status=502,
                content_type="text/plain; charset=utf-8",
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

    def _chat_display_name(peer: Any) -> str:
        try:
            peer_dict = peer.to_dict()
            alias = str(peer_dict.get("chat_alias") or "").strip()
            if alias:
                return alias
            return str(peer_dict.get("display_name") or "").strip() or peer.node_id[:12]
        except Exception:
            return display_name_for_peer(getattr(peer, "node_id", ""), getattr(peer, "name", None))

    def _chat_peer_available(peer: Any) -> bool:
        try:
            return bool(peer.to_dict().get("chat_enabled", True))
        except Exception:
            return bool(getattr(peer, "chat_enabled", True))

    def _chat_summary_payload() -> dict[str, Any]:
        if not _chat_enabled():
            return {"ok": True, "chat_enabled": False, "chat_alias": _chat_alias(), "total_unread": 0, "conversations": []}
        peers = [peer for peer in _list_active_peers() if _chat_peer_available(peer)]
        conversations = []
        total_unread = 0
        with chat_lock:
            for peer in peers:
                messages = list(chat_messages.get(peer.node_id, []))
                last_message = messages[-1] if messages else None
                unread = int(chat_unread.get(peer.node_id, 0))
                total_unread += unread
                conversations.append({
                    "peer_id": peer.node_id,
                    "display_name": _chat_display_name(peer),
                    "unread": unread,
                    "last_message": last_message,
                })
        return {"ok": True, "chat_enabled": True, "chat_alias": _chat_alias(), "total_unread": total_unread, "conversations": conversations}

    def _safe_chat_attachment(payload: dict[str, Any], peer_id: str) -> dict[str, Any] | None:
        attachment = payload.get("attachment")
        if not isinstance(attachment, dict):
            return None
        kind = str(attachment.get("kind", "")).strip().lower()
        if kind == "image":
            name = str(attachment.get("name", "Bild")).strip()[:120] or "Bild"
            mime = str(attachment.get("mime", "image/png")).strip()[:80] or "image/png"
            data_url = str(attachment.get("data_url", "")).strip()
            if not data_url.startswith("data:image/") or len(data_url) > 4_500_000:
                raise StorageError("Bildanhang ist zu groß oder ungültig. Maximal ca. 3 MiB pro Chat-Bild.")
            return {"kind": "image", "name": name, "mime": mime, "data_url": data_url}
        if kind == "file":
            manifest_id = str(attachment.get("manifest_id", "")).strip()
            if not manifest_id:
                raise StorageError("Dateianhang fehlt")
            manifest = manifest_store.load(manifest_id)
            if not manifest_store.may_access(manifest, identity.node_id):
                raise StorageError("Datei ist auf diesem Knoten nicht sichtbar")
            if manifest.owner_node_id == identity.node_id:
                manifest = manifest_store.set_shared(manifest.manifest_id, True, identity, shared_with=[peer_id])
                peer = next((item for item in _list_active_peers() if item.node_id == peer_id), None)
                if peer is not None:
                    p2p_client.post_manifest(peer, manifest)
            return {
                "kind": "file",
                "manifest_id": manifest.manifest_id,
                "file_name": manifest.file_name,
                "file_size": manifest.file_size,
                "download_url": url_for("download", manifest_id=manifest.manifest_id),
            }
        raise StorageError("Unbekannter Chat-Anhang")

    def _find_chat_peer(peer_id: str) -> Any | None:
        return next((item for item in _list_active_peers() if item.node_id == peer_id), None)

    def _set_chat_message_status(peer_id: str, message_id: str, status: str, **extra: Any) -> bool:
        changed = False
        with chat_lock:
            for msg in chat_messages.get(peer_id, []):
                if str(msg.get("id")) == message_id:
                    msg["status"] = status
                    msg.update({key: value for key, value in extra.items() if value is not None})
                    changed = True
                    break
        return changed

    def _enqueue_chat_delivery(peer_id: str, payload: dict[str, Any], *, attempt: int = 0) -> None:
        with chat_delivery_lock:
            chat_delivery_queue.append({
                "peer_id": peer_id,
                "payload": payload,
                "attempt": int(attempt),
                "next_at": time.time(),
            })
            chat_delivery_event.set()
        _ensure_chat_delivery_worker()

    def _ensure_chat_delivery_worker() -> None:
        nonlocal chat_delivery_worker_started
        if chat_delivery_worker_started:
            return
        with chat_delivery_lock:
            if chat_delivery_worker_started:
                return
            chat_delivery_worker_started = True
        worker = threading.Thread(target=_chat_delivery_worker_loop, name="chat-delivery", daemon=True)
        worker.start()

    def _chat_delivery_worker_loop() -> None:
        while True:
            chat_delivery_event.wait(timeout=10.0)
            chat_delivery_event.clear()
            while True:
                item: dict[str, Any] | None = None
                with chat_delivery_lock:
                    now = time.time()
                    for idx, candidate in enumerate(list(chat_delivery_queue)):
                        if float(candidate.get("next_at") or 0) <= now:
                            item = candidate
                            try:
                                del chat_delivery_queue[idx]
                            except Exception:
                                pass
                            break
                    if item is None:
                        next_times = [float(candidate.get("next_at") or 0) for candidate in chat_delivery_queue]
                        if next_times:
                            delay = max(0.5, min(10.0, min(next_times) - time.time()))
                            threading.Timer(delay, chat_delivery_event.set).start()
                        break
                if item is not None:
                    _deliver_chat_queue_item(item)

    def _deliver_chat_queue_item(item: dict[str, Any]) -> None:
        peer_id = str(item.get("peer_id") or "").strip()
        payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
        message_id = str(payload.get("id") or "").strip()
        if not peer_id or not message_id:
            return
        peer = _find_chat_peer(peer_id)
        if peer is None or not _chat_peer_available(peer):
            attempt = int(item.get("attempt") or 0) + 1
            if attempt <= 10:
                item["attempt"] = attempt
                item["next_at"] = time.time() + min(300, 3 * attempt * attempt)
                with chat_delivery_lock:
                    chat_delivery_queue.append(item)
            else:
                _set_chat_message_status(peer_id, message_id, "failed", error="Peer ist nicht erreichbar oder Chat ist deaktiviert")
            return
        transfer = p2p_client._post_json_to_peer(  # noqa: SLF001
            peer,
            path="/api/p2p/chat",
            payload=payload,
            success_message="chat delivered",
            log_message="Chat message to peer %s failed",
        )
        if transfer.ok:
            _set_chat_message_status(peer_id, message_id, "sent", delivered_at=datetime.now(timezone.utc).isoformat())
            return
        attempt = int(item.get("attempt") or 0) + 1
        if attempt <= 10:
            item["attempt"] = attempt
            item["next_at"] = time.time() + min(300, 3 * attempt * attempt)
            with chat_delivery_lock:
                chat_delivery_queue.append(item)
            chat_delivery_event.set()
        else:
            _set_chat_message_status(peer_id, message_id, "failed", error=transfer.message or "Zustellung fehlgeschlagen")

    def _send_chat_read_receipt(peer_id: str, message_ids: list[str]) -> None:
        if not message_ids:
            return
        peer = _find_chat_peer(peer_id)
        if peer is None or not _chat_peer_available(peer):
            return
        payload = {
            "from_node_id": identity.node_id,
            "to_node_id": peer_id,
            "message_ids": list(dict.fromkeys(message_ids))[:100],
            "read_at": datetime.now(timezone.utc).isoformat(),
        }
        def worker() -> None:
            try:
                p2p_client._post_json_to_peer(  # noqa: SLF001
                    peer,
                    path="/api/p2p/chat/read-receipt",
                    payload=payload,
                    success_message="chat read receipt delivered",
                    log_message="Chat read receipt to peer %s failed",
                )
            except Exception:
                pass
        threading.Thread(target=worker, name="chat-read-receipt", daemon=True).start()

    @app.get("/api/chat/summary")
    def api_chat_summary() -> Response:
        return jsonify(_chat_summary_payload())

    @app.get("/api/chat")
    def api_chat_list() -> Response:
        if not _chat_enabled():
            return jsonify({"ok": False, "message": "Chat ist auf diesem Peer deaktiviert", "chat_enabled": False}), 403
        peer_id = str(request.args.get("peer_id", "")).strip()
        if not peer_id:
            return jsonify({"ok": False, "message": "peer_id fehlt"}), 400
        read_ids: list[str] = []
        with chat_lock:
            for msg in chat_messages.get(peer_id, []):
                if msg.get("direction") == "in" and not msg.get("read_at"):
                    msg["read_at"] = datetime.now(timezone.utc).isoformat()
                    read_ids.append(str(msg.get("id")))
            chat_unread[peer_id] = 0
            messages = list(chat_messages.get(peer_id, []))
        _send_chat_read_receipt(peer_id, read_ids)
        return jsonify({"ok": True, "peerId": peer_id, "messages": messages, "summary": _chat_summary_payload()})

    @app.post("/api/chat/read")
    def api_chat_mark_read() -> Response:
        if not _chat_enabled():
            return jsonify({"ok": False, "message": "Chat ist auf diesem Peer deaktiviert", "chat_enabled": False}), 403
        payload = request.get_json(silent=True) or {}
        peer_id = str(payload.get("peer_id", "")).strip()
        read_ids: list[str] = []
        if peer_id:
            with chat_lock:
                for msg in chat_messages.get(peer_id, []):
                    if msg.get("direction") == "in" and not msg.get("read_at"):
                        msg["read_at"] = datetime.now(timezone.utc).isoformat()
                        read_ids.append(str(msg.get("id")))
                chat_unread[peer_id] = 0
            _send_chat_read_receipt(peer_id, read_ids)
        return jsonify(_chat_summary_payload())

    @app.post("/api/chat/send")
    def api_chat_send() -> Response:
        if not _chat_enabled():
            return jsonify({"ok": False, "message": "Chat ist auf diesem Peer deaktiviert", "chat_enabled": False}), 403
        payload = request.get_json(silent=True) or {}
        peer_id = str(payload.get("peer_id", "")).strip()
        text = str(payload.get("text", "")).strip()
        if not peer_id:
            return jsonify({"ok": False, "message": "peer_id fehlt"}), 400
        attachment = None
        try:
            attachment = _safe_chat_attachment(payload, peer_id)
        except StorageError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400
        if not text and not attachment:
            return jsonify({"ok": False, "message": "Nachricht oder Anhang erforderlich"}), 400
        peer = _find_chat_peer(peer_id)
        if peer is None:
            return jsonify({"ok": False, "message": "Peer ist nicht aktiv erreichbar"}), 404
        if not _chat_peer_available(peer):
            return jsonify({"ok": False, "message": "Dieser Peer hat den Chat deaktiviert"}), 409
        now = datetime.now(timezone.utc).isoformat()
        outgoing = {
            "id": uuid4().hex,
            "from_node_id": identity.node_id,
            "from_alias": _chat_alias(),
            "to_node_id": peer_id,
            "text": text,
            "attachment": attachment,
            "created_at": now,
        }
        local_event = {**outgoing, "direction": "out", "status": "sending"}
        with chat_lock:
            chat_messages[peer_id].append(local_event)
        _enqueue_chat_delivery(peer_id, outgoing)
        return jsonify({"ok": True, "queued": True, "message": local_event, "summary": _chat_summary_payload()})

    def _requested_storage_peers() -> list[Any]:
        available_peers = _eligible_storage_peers()
        requested_peer_ids = [str(peer_id).strip() for peer_id in request.form.getlist("storage_peer_node_ids") if str(peer_id).strip()]
        explicit_selection = request.form.get("storage_peer_selection_mode") == "manual"
        if not requested_peer_ids:
            # No IDs used to mean "default to all peers".  The dashboard now sends
            # storage_peer_selection_mode=manual when the user intentionally turned
            # all peer targets off, so local-only uploads are possible without the
            # next refresh silently selecting every peer again.
            return [] if explicit_selection else available_peers
        requested_set = set(requested_peer_ids)
        selected = [peer for peer in available_peers if peer.node_id in requested_set]
        return selected if explicit_selection else (selected or available_peers)

    def _local_first_upload_placement(upload_result: Any, storage_peers: list[Any]) -> dict[str, Any]:
        peer_ids = [peer.node_id for peer in storage_peers]
        targets = list(dict.fromkeys([identity.node_id, *peer_ids]))
        background_enabled = bool(storage_peers)
        desired_replicas = dynamic_mirror_replica_count(len(storage_peers)) if background_enabled else 1
        return {
            "strategy": "local_first_background_replication",
            "target_count": len(targets),
            "targets": targets,
            "transfer_status": "background_replication_queued" if background_enabled else upload_result.transfer_status,
            "remote_successes": 0,
            "remote_failures": 0,
            "local_chunks": upload_result.local_chunks,
            "compressed_chunks": upload_result.compressed_chunks,
            "raid_level": 1,
            "raid_mode": "dynamic_mirror",
            "desired_replicas": desired_replicas,
            "dynamic_mirror_cap": 4,
            "replicated_chunks": 0,
            "under_replicated_chunks": len(upload_result.chunks) if background_enabled else 0,
            "raw_bytes": upload_result.raw_bytes,
            "stored_bytes": upload_result.stored_bytes,
            "background_replication": background_enabled,
            "background_queued_at": datetime.now(timezone.utc).isoformat() if background_enabled else None,
        }

    def _local_chunk_store_can_fit(file_size: int) -> bool:
        try:
            stats = chunk_store.stats()
        except Exception:
            return True
        needed = max(0, int(file_size or 0))
        if needed <= 0:
            return True
        if stats.free_limit_bytes < needed:
            return False
        if stats.filesystem_free_bytes - needed < stats.min_free_bytes:
            return False
        return True

    def _remote_primary_upload_placement(upload_result: Any, storage_peers: list[Any], primary: Any, delegation_info: dict[str, Any] | None = None) -> dict[str, Any]:
        peer_ids = [peer.node_id for peer in storage_peers]
        targets = list(dict.fromkeys([*peer_ids]))
        desired_replicas = dynamic_mirror_replica_count(len(storage_peers)) if storage_peers else 1
        return {
            "strategy": "remote_primary_delegated_upload",
            "target_count": len(targets),
            "targets": targets,
            "transfer_status": upload_result.transfer_status,
            "remote_successes": upload_result.remote_successes,
            "remote_failures": upload_result.remote_failures,
            "local_chunks": upload_result.local_chunks,
            "compressed_chunks": upload_result.compressed_chunks,
            "raid_level": 1,
            "raid_mode": "dynamic_mirror",
            "desired_replicas": desired_replicas,
            "dynamic_mirror_cap": 4,
            "replicated_chunks": upload_result.replicated_chunks,
            "under_replicated_chunks": upload_result.under_replicated_chunks,
            "raw_bytes": upload_result.raw_bytes,
            "stored_bytes": upload_result.stored_bytes,
            "background_replication": False,
            "primary_peer_id": primary.node_id,
            "delegated_replication": delegation_info or {"delegated": False, "primary_peer_id": primary.node_id},
            "remote_primary_uploaded_at": datetime.now(timezone.utc).isoformat(),
        }

    def _run_remote_primary_upload(
        *,
        temp_path: Path,
        safe_name: str,
        folder_path: str,
        upload_id: str,
        storage_peers: list[Any],
    ) -> tuple[FileManifest, Any, str]:
        if not storage_peers:
            raise StorageError("Lokaler Speicher ist voll und es ist kein erreichbarer Speicher-Peer aktiv")
        file_size = temp_path.stat().st_size
        ranked = rank_peers_by_speed(storage_peers, p2p_client)
        if not ranked:
            raise StorageError("Lokaler Speicher ist voll und kein Direct-/Gateway-Speicher-Peer ist erreichbar")
        primary = ranked[0]
        upload_progress.update(
            upload_id,
            phase="remote_primary_upload",
            status="Lokaler Speicher reicht nicht; Datei wird einmalig an den schnellsten Peer übertragen…",
            percent=45,
            server_percent=8,
            total_bytes=file_size,
            target_count=len(ranked),
            current_peer=primary.to_dict().get("display_name") or primary.node_id[:12],
            details={"remotePrimaryUpload": True, "primaryPeer": primary.node_id},
        )
        upload_result = distribute_file_chunks(
            source_path=temp_path,
            chunk_store=chunk_store,
            local_node_id=identity.node_id,
            peers=[primary],
            p2p_client=p2p_client,
            progress_callback=_upload_server_progress(upload_id),
            chunk_size_bytes=chunk_store.chunk_size,
        )
        primary_chunks = sum(1 for chunk in upload_result.chunks if primary.node_id in [str(node_id) for node_id in chunk.get("locations", [])])
        if primary_chunks != len(upload_result.chunks):
            raise StorageError("Remote-Upload fehlgeschlagen: der erste Peer hat nicht alle Chunks bestätigt")
        placement = _remote_primary_upload_placement(upload_result, ranked, primary)
        upload_progress.update(
            upload_id,
            phase="manifest",
            status="Remote-Manifest wird geschrieben; der erste Peer verteilt danach intern weiter…",
            percent=96,
            server_percent=92,
            raw_bytes_processed=upload_result.raw_bytes,
            stored_bytes=upload_result.stored_bytes,
            compressed_chunks=upload_result.compressed_chunks,
            local_chunks=upload_result.local_chunks,
            remote_successes=upload_result.remote_successes,
            remote_failures=upload_result.remote_failures,
            desired_replicas=placement["desired_replicas"],
            target_count=len(placement["targets"]),
            details={"remotePrimaryUpload": True, "primaryPeer": primary.node_id},
        )
        manifest = manifest_store.create_from_chunk_entries(
            file_name=safe_name,
            file_size=file_size,
            chunk_entries=upload_result.chunks,
            identity=identity,
            folder_path=folder_path,
            placement=placement,
        )
        delegation_info: dict[str, Any] = {
            "delegated": False,
            "primary_peer_id": primary.node_id,
            "primary_chunks": primary_chunks,
            "candidate_peer_count": len(ranked),
        }
        if len(ranked) > 1:
            try:
                payload = p2p_client.post_replication_delegation(
                    primary,
                    manifest=manifest,
                    exclude_node_ids=[identity.node_id],
                )
                upload_result = _merge_peer_delegation_payload(upload_result, payload)
                delegation_info.update({
                    "delegated": True,
                    "delegated_peer_count": int(payload.get("peer_count") or 0),
                    "delegated_remote_successes": int(payload.get("remote_successes") or 0),
                    "delegated_remote_failures": int(payload.get("remote_failures") or 0),
                })
                placement = _remote_primary_upload_placement(upload_result, ranked, primary, delegation_info)
                manifest = manifest_store.update_placement(
                    manifest.manifest_id,
                    identity,
                    chunks=upload_result.chunks,
                    placement=placement,
                )
            except StorageError as exc:
                delegation_info["delegation_error"] = str(exc)
                placement = _remote_primary_upload_placement(upload_result, ranked, primary, delegation_info)
                manifest = manifest_store.update_placement(
                    manifest.manifest_id,
                    identity,
                    placement=placement,
                )
        message = (
            f"Datei remote gespeichert: {safe_name}; Primär-Peer {primary.to_dict().get('display_name') or primary.node_id[:12]} "
            "übernimmt die weitere Direct-/Gateway-Verteilung."
        )
        upload_progress.finish(
            upload_id,
            ok=True,
            message=message,
            details={
                "manifestId": manifest.manifest_id,
                "transferStatus": upload_result.transfer_status,
                "remotePrimaryUpload": True,
                "primaryPeer": primary.node_id,
                "delegatedReplication": delegation_info,
            },
        )
        return manifest, upload_result, message

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
        if storage_peers and not _local_chunk_store_can_fit(file_size):
            return _run_remote_primary_upload(
                temp_path=temp_path,
                safe_name=safe_name,
                folder_path=folder_path,
                upload_id=upload_id,
                storage_peers=storage_peers,
            )
        upload_progress.update(
            upload_id,
            phase="local_chunking",
            status="Datei wird lokal gespeichert; Peer-Verteilung startet danach im Hintergrund…",
            percent=45,
            server_percent=8,
            details={"backgroundReplication": bool(storage_peers)},
        )
        try:
            upload_result = distribute_file_chunks(
                source_path=temp_path,
                chunk_store=chunk_store,
                local_node_id=identity.node_id,
                peers=[],
                p2p_client=p2p_client,
                progress_callback=_upload_server_progress(upload_id),
                chunk_size_bytes=chunk_store.chunk_size,
            )
        except StorageError:
            if not storage_peers:
                raise
            upload_progress.update(
                upload_id,
                phase="remote_primary_upload",
                status="Lokaler Speicher wurde während des Schreibens knapp; Wechsel auf Remote-Primary-Upload…",
                percent=45,
                server_percent=8,
                details={"remotePrimaryUpload": True, "fallbackAfterLocalFull": True},
            )
            return _run_remote_primary_upload(
                temp_path=temp_path,
                safe_name=safe_name,
                folder_path=folder_path,
                upload_id=upload_id,
                storage_peers=storage_peers,
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

    def _large_upload_session_meta_path(upload_id: str) -> Path:
        return large_upload_sessions_dir / f"{_safe_upload_id(upload_id)}.json"

    def _large_upload_session_temp_path(upload_id: str) -> Path:
        return large_upload_sessions_dir / f"{_safe_upload_id(upload_id)}.part"

    def _load_large_upload_session(upload_id: str) -> dict[str, Any]:
        path = _large_upload_session_meta_path(upload_id)
        if not path.exists():
            raise StorageError("Upload-Sitzung wurde nicht gefunden. Bitte Upload neu starten.")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError) as exc:
            raise StorageError("Upload-Sitzung ist beschädigt. Bitte Upload neu starten.") from exc
        if not isinstance(payload, dict):
            raise StorageError("Upload-Sitzung ist ungültig. Bitte Upload neu starten.")
        return payload

    def _save_large_upload_session(upload_id: str, payload: dict[str, Any]) -> None:
        path = _large_upload_session_meta_path(upload_id)
        tmp_path = path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        tmp_path.replace(path)

    def _cleanup_large_upload_session(upload_id: str, *, remove_temp: bool = True) -> None:
        _large_upload_session_meta_path(upload_id).unlink(missing_ok=True)
        if remove_temp:
            _large_upload_session_temp_path(upload_id).unlink(missing_ok=True)

    def _storage_peers_from_selection(selection_mode: str | None, peer_ids: list[str] | None) -> list[Any]:
        available_peers = _eligible_storage_peers()
        requested_peer_ids = [str(peer_id).strip() for peer_id in (peer_ids or []) if str(peer_id).strip()]
        explicit_selection = str(selection_mode or "").strip().lower() == "manual"
        if not requested_peer_ids:
            return [] if explicit_selection else available_peers
        requested_set = set(requested_peer_ids)
        selected = [peer for peer in available_peers if peer.node_id in requested_set]
        return selected if explicit_selection else (selected or available_peers)

    def _validate_large_upload_size(file_size: int) -> None:
        if file_size < 0:
            raise StorageError("Dateigröße ist ungültig")
        if file_size > LARGE_UPLOAD_MAX_BYTES:
            raise StorageError(f"Datei ist zu groß. Maximal erlaubt: {human_bytes(LARGE_UPLOAD_MAX_BYTES)}")
        # Local-first uploads need temporary space while chunking runs.  Keep this
        # check conservative but not overly strict: the final compressed chunks may
        # be smaller than the raw file, but the temporary stream must fit first.
        try:
            free_bytes = shutil.disk_usage(chunk_store.tmp_dir).free
            if free_bytes - file_size < chunk_store.min_free_bytes:
                raise StorageError("Nicht genug freier Speicherplatz für den temporären Upload")
        except FileNotFoundError:
            pass

    @app.post("/api/uploads/chunk/start")
    def api_large_upload_start() -> Response:
        payload = request.get_json(silent=True) or {}
        upload_id = _safe_upload_id(payload.get("upload_id"))
        try:
            safe_name = secure_filename(str(payload.get("file_name") or "")) or "upload.bin"
            folder_path = sanitize_folder_path(payload.get("folder", DEFAULT_FOLDER))
            if folder_path == INCOMING_SHARES_FOLDER or folder_path.startswith(f"{INCOMING_SHARES_FOLDER}/"):
                raise StorageError("In den Ordner für Peer-Freigaben kann nicht hochgeladen werden")
            file_size = int(payload.get("file_size") or 0)
            _validate_large_upload_size(file_size)
            peer_ids = payload.get("storage_peer_node_ids")
            if not isinstance(peer_ids, list):
                peer_ids = []
            session_payload = {
                "upload_id": upload_id,
                "file_name": safe_name,
                "folder_path": folder_path,
                "file_size": file_size,
                "received_bytes": 0,
                "storage_peer_selection_mode": str(payload.get("storage_peer_selection_mode") or "auto"),
                "storage_peer_node_ids": [str(peer_id) for peer_id in peer_ids if str(peer_id)],
                "created_at": time.time(),
                "updated_at": time.time(),
            }
            with large_upload_session_lock:
                _cleanup_large_upload_session(upload_id, remove_temp=True)
                _save_large_upload_session(upload_id, session_payload)
                _large_upload_session_temp_path(upload_id).parent.mkdir(parents=True, exist_ok=True)
                _large_upload_session_temp_path(upload_id).touch()
            upload_progress.start(upload_id, file_name=safe_name, folder_path=folder_path, total_bytes=file_size)
            upload_progress.update(
                upload_id,
                phase="receiving_chunks",
                status="Großer Upload gestartet; Datei wird in Teilen übertragen…",
                percent=0,
                server_percent=0,
                raw_bytes_processed=0,
                total_bytes=file_size,
                details={"chunkedUpload": True, "chunkSize": LARGE_UPLOAD_CHUNK_BYTES},
            )
            return jsonify({
                "ok": True,
                "uploadId": upload_id,
                "chunkSize": LARGE_UPLOAD_CHUNK_BYTES,
                "receivedBytes": 0,
                "uploadProgress": upload_progress.get(upload_id),
            })
        except (StorageError, ValueError) as exc:
            upload_progress.finish(upload_id, ok=False, message=str(exc))
            _cleanup_large_upload_session(upload_id, remove_temp=True)
            return jsonify({"ok": False, "message": str(exc), "uploadId": upload_id, "uploadProgress": upload_progress.get(upload_id)}), 400

    @app.post("/api/uploads/chunk/<upload_id>")
    def api_large_upload_chunk(upload_id: str) -> Response:
        upload_id = _safe_upload_id(upload_id)
        try:
            try:
                offset = int(request.headers.get("X-DCloud-Chunk-Offset") or request.args.get("offset") or 0)
            except ValueError as exc:
                raise StorageError("Chunk-Offset ist ungültig") from exc
            try:
                declared_index = int(request.headers.get("X-DCloud-Chunk-Index") or request.args.get("index") or 0)
            except ValueError:
                declared_index = 0
            content_length = int(request.content_length or 0)
            if content_length <= 0:
                raise StorageError("Leerer Upload-Chunk")
            if content_length > max(LARGE_UPLOAD_CHUNK_BYTES * 2, 1):
                raise StorageError("Upload-Chunk ist zu groß")

            with large_upload_session_lock:
                meta = _load_large_upload_session(upload_id)
                file_size = int(meta.get("file_size") or 0)
                temp_path = _large_upload_session_temp_path(upload_id)
                current_size = temp_path.stat().st_size if temp_path.exists() else 0
                if offset < current_size and offset + content_length <= current_size:
                    # Browser retry of an already accepted chunk. Consume and
                    # acknowledge without appending duplicate bytes.
                    remaining = content_length
                    while remaining > 0:
                        data = request.stream.read(min(LARGE_UPLOAD_STREAM_BUFFER_BYTES, remaining))
                        if not data:
                            break
                        remaining -= len(data)
                    return jsonify({"ok": True, "uploadId": upload_id, "receivedBytes": current_size, "duplicate": True})
                if offset != current_size:
                    return jsonify({
                        "ok": False,
                        "message": "Upload-Chunk ist nicht an der erwarteten Position angekommen",
                        "expectedOffset": current_size,
                        "receivedBytes": current_size,
                    }), 409
                if current_size + content_length > file_size:
                    raise StorageError("Upload überschreitet die gemeldete Dateigröße")

                temp_path.parent.mkdir(parents=True, exist_ok=True)
                bytes_written = 0
                try:
                    with temp_path.open("ab") as handle:
                        while True:
                            data = request.stream.read(LARGE_UPLOAD_STREAM_BUFFER_BYTES)
                            if not data:
                                break
                            handle.write(data)
                            bytes_written += len(data)
                        handle.flush()
                        os.fsync(handle.fileno())
                except Exception:
                    try:
                        with temp_path.open("r+b") as handle:
                            handle.truncate(current_size)
                    except OSError:
                        pass
                    raise
                if bytes_written != content_length:
                    try:
                        with temp_path.open("r+b") as handle:
                            handle.truncate(current_size)
                    except OSError:
                        pass
                    raise StorageError("Upload-Chunk wurde unvollständig übertragen")
                received = current_size + bytes_written
                meta["received_bytes"] = received
                meta["updated_at"] = time.time()
                _save_large_upload_session(upload_id, meta)

            browser_percent = (received / file_size * 35.0) if file_size else 0.0
            upload_progress.update(
                upload_id,
                phase="receiving_chunks",
                status=f"Datei wird in Teilen übertragen… {human_bytes(received)} von {human_bytes(file_size)}",
                percent=browser_percent,
                server_percent=0,
                raw_bytes_processed=received,
                total_bytes=file_size,
                current_chunk=max(1, declared_index + 1),
                total_chunks=max(1, (file_size + LARGE_UPLOAD_CHUNK_BYTES - 1) // LARGE_UPLOAD_CHUNK_BYTES) if file_size else 1,
            )
            return jsonify({"ok": True, "uploadId": upload_id, "receivedBytes": received, "uploadProgress": upload_progress.get(upload_id)})
        except StorageError as exc:
            upload_progress.finish(upload_id, ok=False, message=str(exc))
            return jsonify({"ok": False, "message": str(exc), "uploadId": upload_id, "uploadProgress": upload_progress.get(upload_id)}), 400

    @app.post("/api/uploads/chunk/<upload_id>/finish")
    def api_large_upload_finish(upload_id: str) -> Response:
        upload_id = _safe_upload_id(upload_id)
        temp_path = _large_upload_session_temp_path(upload_id)
        try:
            with large_upload_session_lock:
                meta = _load_large_upload_session(upload_id)
                file_size = int(meta.get("file_size") or 0)
                received = temp_path.stat().st_size if temp_path.exists() else 0
                if received != file_size:
                    return jsonify({
                        "ok": False,
                        "message": "Upload ist noch nicht vollständig übertragen",
                        "receivedBytes": received,
                        "expectedBytes": file_size,
                        "uploadProgress": upload_progress.get(upload_id),
                    }), 409
            safe_name = str(meta.get("file_name") or "upload.bin")
            folder_path = sanitize_folder_path(meta.get("folder_path") or DEFAULT_FOLDER)
            storage_peers = _storage_peers_from_selection(
                str(meta.get("storage_peer_selection_mode") or "auto"),
                [str(peer_id) for peer_id in meta.get("storage_peer_node_ids") or []],
            )
            upload_progress.update(
                upload_id,
                phase="saving_temp",
                status="Upload vollständig übertragen; Datei wird jetzt lokal verarbeitet…",
                percent=38,
                server_percent=2,
                total_bytes=file_size,
                raw_bytes_processed=file_size,
            )
            manifest, upload_result, message = _run_local_first_upload(
                temp_path=temp_path,
                safe_name=safe_name,
                folder_path=folder_path,
                upload_id=upload_id,
                storage_peers=storage_peers,
            )
            return jsonify({
                "ok": True,
                "message": message,
                "manifest": manifest_payload(manifest),
                "state": state_payload(),
                "uploadId": upload_id,
                "uploadProgress": upload_progress.get(upload_id),
            })
        except StorageError as exc:
            upload_progress.finish(upload_id, ok=False, message=str(exc))
            return jsonify({"ok": False, "message": str(exc), "uploadId": upload_id, "uploadProgress": upload_progress.get(upload_id)}), 400
        finally:
            _cleanup_large_upload_session(upload_id, remove_temp=True)

    @app.post("/api/uploads/chunk/<upload_id>/abort")
    def api_large_upload_abort(upload_id: str) -> Response:
        upload_id = _safe_upload_id(upload_id)
        _cleanup_large_upload_session(upload_id, remove_temp=True)
        upload_progress.finish(upload_id, ok=False, message="Upload abgebrochen")
        return jsonify({"ok": True, "uploadId": upload_id, "uploadProgress": upload_progress.get(upload_id)})

    @app.get("/api/web/files")
    def api_web_files() -> Response:
        return jsonify({"ok": True, "webFiles": web_files_payload()})

    @app.get("/api/web/file")
    def api_web_file() -> Response:
        try:
            path = _safe_web_file_path(request.args.get("path"))
            if not path.exists() or not path.is_file():
                raise StorageError("Web-Datei nicht gefunden")
            if not _is_web_text_editable(path):
                raise StorageError("Diese Datei ist kein bearbeitbarer Texttyp")
            if path.stat().st_size > WEB_EDIT_MAX_BYTES:
                raise StorageError("Diese Datei ist zu groß für den integrierten Texteditor")
            return jsonify({
                "ok": True,
                "path": path.relative_to(web_root.resolve()).as_posix(),
                "name": path.name,
                "content": path.read_text(encoding="utf-8"),
                "modifiedAt": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
            })
        except UnicodeDecodeError:
            return jsonify({"ok": False, "message": "Datei ist nicht als UTF-8-Text lesbar"}), 400
        except StorageError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400

    @app.post("/api/web/file")
    def api_web_save_file() -> Response:
        payload = request.get_json(silent=True) or {}
        try:
            path = _safe_web_file_path(payload.get("path"))
            if not path.exists() or not path.is_file():
                raise StorageError("Web-Datei nicht gefunden")
            if not _is_web_text_editable(path):
                raise StorageError("Diese Datei ist kein bearbeitbarer Texttyp")
            content = str(payload.get("content", ""))
            if len(content.encode("utf-8")) > WEB_EDIT_MAX_BYTES:
                raise StorageError("Datei ist zu groß für den integrierten Texteditor")
            path.write_text(content, encoding="utf-8")
            return _web_json_state(f"Web-Datei gespeichert: {path.name}")
        except StorageError as exc:
            return jsonify({"ok": False, "message": str(exc), "webFiles": web_files_payload()}), 400

    @app.post("/api/web/upload")
    def api_web_upload() -> Response:
        uploaded = request.files.get("file")
        if uploaded is None or uploaded.filename == "":
            return jsonify({"ok": False, "message": "Keine Datei ausgewählt", "webFiles": web_files_payload()}), 400
        try:
            folder = _normalize_web_relative(request.form.get("folder", ""), allow_empty=True)
            target_dir = _safe_web_file_path(folder, allow_directory=True, allow_empty=True)
            target_dir.mkdir(parents=True, exist_ok=True)
            safe_name = secure_filename(uploaded.filename) or "upload.bin"
            target_path = (target_dir / safe_name).resolve()
            root = web_root.resolve()
            if root not in target_path.parents:
                raise StorageError("Web-Pfad ist ungültig")
            uploaded.save(target_path)
            return _web_json_state(f"Web-Datei hochgeladen: {safe_name}")
        except StorageError as exc:
            return jsonify({"ok": False, "message": str(exc), "webFiles": web_files_payload()}), 400

    @app.post("/api/web/folders")
    def api_web_create_folder() -> Response:
        payload = request.get_json(silent=True) or request.form
        try:
            folder = _normalize_web_relative(payload.get("folder"), allow_empty=False)
            target = _safe_web_file_path(folder, allow_directory=True)
            target.mkdir(parents=True, exist_ok=True)
            return _web_json_state(f"Web-Ordner erstellt: {folder}")
        except StorageError as exc:
            return jsonify({"ok": False, "message": str(exc), "webFiles": web_files_payload()}), 400

    @app.post("/api/web/delete")
    def api_web_delete() -> Response:
        payload = request.get_json(silent=True) or request.form
        try:
            target = _safe_web_file_path(payload.get("path"), allow_directory=True)
            if target == web_root.resolve():
                raise StorageError("Der Web-Hauptordner kann nicht gelöscht werden")
            if not target.exists():
                raise StorageError("Web-Datei oder Web-Ordner nicht gefunden")
            if target.is_dir():
                shutil.rmtree(target)
                message = f"Web-Ordner gelöscht: {target.name}"
            else:
                target.unlink()
                message = f"Web-Datei gelöscht: {target.name}"
            return _web_json_state(message)
        except StorageError as exc:
            return jsonify({"ok": False, "message": str(exc), "webFiles": web_files_payload()}), 400

    @app.get("/api/browser/downloads")
    def api_browser_downloads() -> Response:
        return jsonify({"ok": True, "browserDownloads": browser_downloads_payload()})

    @app.get("/api/browser/downloads/file")
    def api_browser_download_file() -> Response:
        try:
            path = _safe_browser_download_path(request.args.get("path"))
            if not path.exists() or not path.is_file():
                raise StorageError("Download-Datei nicht gefunden")
            inline = str(request.args.get("inline") or "").lower() in {"1", "true", "yes"}
            return send_file(path, as_attachment=not inline, download_name=path.name, conditional=True)
        except StorageError as exc:
            return Response(str(exc), status=404, content_type="text/plain; charset=utf-8")

    @app.post("/api/browser/downloads/delete")
    def api_browser_download_delete() -> Response:
        payload = request.get_json(silent=True) or request.form
        try:
            target = _safe_browser_download_path(payload.get("path"), allow_directory=True)
            if target == browser_downloads_root.resolve():
                raise StorageError("Der Downloads-Hauptordner kann nicht gelöscht werden")
            if not target.exists():
                raise StorageError("Download-Datei oder Download-Ordner nicht gefunden")
            if target.is_dir():
                shutil.rmtree(target)
                message = f"Download-Ordner gelöscht: {target.name}"
            else:
                target.unlink()
                message = f"Download gelöscht: {target.name}"
            return _browser_download_json_state(message)
        except StorageError as exc:
            return jsonify({"ok": False, "message": str(exc), "browserDownloads": browser_downloads_payload()}), 400

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
        normalized_folder = sanitize_folder_path(folder_path)
        if normalized_folder == INCOMING_SHARES_FOLDER or normalized_folder.startswith(f"{INCOMING_SHARES_FOLDER}/"):
            message = "Der Systemordner für Peer-Freigaben kann nicht manuell verändert werden"
            if _is_ajax_request():
                return jsonify({"ok": False, "message": message, "state": state_payload()}), 400
            flash(message, "error")
            return redirect(redirect_target)
        created = manifest_store.create_folder(normalized_folder, identity.node_id)
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
            if folder_path in {DEFAULT_FOLDER, INCOMING_SHARES_FOLDER}:
                raise StorageError("Dieser Systemordner kann nicht gelöscht werden")
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

            # First transfer the chunks to one primary peer.  That peer then
            # performs the remaining RAID fan-out, so the starter does not upload
            # the same data to every mirror.
            result, delegation_info = _replicate_via_primary_peer(
                manifest=manifest,
                peers=peers,
                require_primary=True,
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
                "strategy": "peer_additional_replica" if add_only else "delegated_peer_offload",
                "delegated_replication": delegation_info,
                "targets": new_targets,
                "target_count": len(new_targets),
                "transfer_status": "replicated_with_local_copy" if add_only else ("stored_on_peers" if removal_candidates else "local_only"),
                "offloaded_local_chunks": 0,
                "offload_requested_chunks": len(manifest.chunks),
                "offload_candidate_chunks": len(removal_candidates),
                "offload_remote_successes": result.remote_successes,
                "offload_remote_failures": result.remote_failures,
                "raid_level": 1,
                "raid_mode": "dynamic_mirror",
                "replicated_chunks": result.replicated_chunks,
                "under_replicated_chunks": result.under_replicated_chunks,
                "desired_replicas": result.desired_replicas,
                "dynamic_mirror_cap": 4,
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
                nat_endpoint = (request.form.get("nat_endpoint") or request.form.get("peer_endpoint") or "").strip()
                if nat_endpoint:
                    manual_peer = _upsert_manual_peer_route(nat_endpoint)
                    target_peers, shared_with = [manual_peer], [manual_peer.node_id]
                else:
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
                        share_delivery_attempts[f"{manifest.manifest_id}:{manifest.signature}:{peer.node_id}"] = time.time()
                    else:
                        failed += 1
                # Also trigger the relay-aware share refresher. This covers peers
                # that appeared through the tracker a moment after the dialog was
                # opened or that are reachable only via Internet.
                try:
                    refresh = _deliver_active_manifest_shares(_list_active_peers(), min_interval_seconds=1)
                    delivered += int(refresh.get("delivered", 0))
                    failed += int(refresh.get("failed", 0))
                except Exception:
                    LOG.debug("Immediate shared-manifest refresh failed", exc_info=True)
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
            if target_folder == INCOMING_SHARES_FOLDER or target_folder.startswith(f"{INCOMING_SHARES_FOLDER}/"):
                raise StorageError("Der Systemordner für Peer-Freigaben ist nur für eingehende Freigaben vorgesehen")
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
            old_smb_settings = (
                bool(config.smb.enabled),
                str(config.smb.username),
                str(config.smb.password),
                str(config.smb.host),
                int(config.smb.port),
                str(config.smb.share_name),
            )
            submitted_smb_password = request.form.get("smb_password")
            smb_runtime_before = app.config.get("DCLOUD_SMB_STATUS") or {}
            update_runtime_settings(
                config,
                client_type="server",
                shared_storage_gb=request.form.get("shared_storage_gb", bytes_to_gib(config.storage.limit_bytes)),
                relay_server_url="",
                relay_server_urls=[],
                relay_enabled=False,
                smb_enabled=request.form.get("smb_enabled") == "on",
                smb_username=request.form.get("smb_username", config.smb.username),
                smb_password=submitted_smb_password if submitted_smb_password else config.smb.password,
                compression_mode=request.form.get("compression_mode", config.storage.compression.mode),
                compression_algorithm=request.form.get("compression_algorithm", config.storage.compression.algorithm),
                compression_level=request.form.get("compression_level", str(config.storage.compression.level)),
                compression_min_savings_percent=request.form.get("compression_min_savings_percent", str(config.storage.compression.min_savings_percent)),
                compression_skip_incompressible=request.form.get("compression_skip_incompressible") == "on",
            )
            chat_settings["enabled"] = request.form.get("chat_enabled") == "on"
            chat_settings["alias"] = _sanitize_chat_alias(request.form.get("chat_alias") or "")
            _persist_chat_settings()
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
            new_smb_settings = (
                bool(config.smb.enabled),
                str(config.smb.username),
                str(config.smb.password),
                str(config.smb.host),
                int(config.smb.port),
                str(config.smb.share_name),
            )
            smb_runtime_note = ""
            if old_smb_settings != new_smb_settings or (config.smb.enabled and not smb_runtime_before.get("running")):
                apply_smb_settings = app.config.get("DCLOUD_APPLY_SMB_SETTINGS")
                if callable(apply_smb_settings):
                    smb_status_after = apply_smb_settings()
                    if config.smb.enabled:
                        if smb_status_after.get("running"):
                            smb_runtime_note = f", SMB neu gestartet auf Port {smb_status_after.get('port', config.smb.port)}"
                        elif smb_status_after.get("last_error"):
                            smb_runtime_note = f", SMB Startfehler: {smb_status_after.get('last_error')}"
                        else:
                            smb_runtime_note = ", SMB wird gestartet"
                    else:
                        smb_runtime_note = ", SMB gestoppt"
                elif config.smb.enabled:
                    smb_runtime_note = ", SMB-Änderung gespeichert; Dienst-Neustart erforderlich"
            relay_note = ", Direct-Peer-Modus"
            message = (
                f"Einstellungen gespeichert: {client_type_label(config.node.client_type)}, "
                f"{bytes_to_gib(config.storage.limit_bytes):g} GB freigegeben{relay_note}, "
                f"Komprimierung {config.storage.compression.mode}/{config.storage.compression.algorithm}, "
                f"SMB {'aktiv' if config.smb.enabled else 'aus'} auf Port {config.smb.port}{smb_runtime_note}"
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
            suffix = f"; {len(errors)} Peer-Connector(s) derzeit nicht erreichbar" if errors else ""
            return jsonify({"ok": True, "message": f"Netzwerksuche gestartet{suffix}", "state": state_payload()})
        message = "; ".join(errors) if errors else "Peer-Discovery ist nicht verfügbar"
        return jsonify({"ok": False, "message": f"Netzwerksuche fehlgeschlagen: {message}", "state": state_payload()}), 503

    @app.post("/api/peer-routes")
    def api_add_peer_route() -> Response:
        payload = request.get_json(silent=True) if request.is_json else request.form
        endpoint = str((payload or {}).get("endpoint") or (payload or {}).get("url") or "").strip()
        display_name = str((payload or {}).get("display_name") or "").strip() or None
        if not endpoint:
            return jsonify({"ok": False, "message": "NAT-/DDNS-Endpunkt fehlt", "state": state_payload()}), 400
        try:
            peer = _upsert_manual_peer_route(endpoint, display_name=display_name)
        except (StorageError, ValueError) as exc:
            return jsonify({"ok": False, "message": str(exc), "state": state_payload()}), 400
        label = display_name_for_peer(peer.node_id, peer.name)
        return jsonify({
            "ok": True,
            "message": f"Direkter Peer gespeichert und aktiver Austausch gestartet: {label}",
            "peer": peer.to_dict(),
            "manualPeerRoutes": _manual_peer_routes_payload(),
            "state": state_payload(),
        })

    @app.post("/api/peer-routes/remove")
    def api_remove_peer_route() -> Response:
        payload = request.get_json(silent=True) if request.is_json else request.form
        node_id = _safe_peer_id(str((payload or {}).get("peer_id") or (payload or {}).get("node_id") or ""))
        if not node_id:
            return jsonify({"ok": False, "message": "peer_id fehlt", "state": state_payload()}), 400
        removed = False
        with manual_peer_routes_lock:
            removed = manual_peer_routes.pop(node_id, None) is not None
            if removed:
                _persist_manual_peer_routes()
        if removed:
            try:
                peer_provider.remove(node_id)
            except Exception:
                pass
        return jsonify({
            "ok": True,
            "message": "Direkter Endpunkt entfernt." if removed else "Kein manueller Endpunkt für diesen Peer gespeichert.",
            "manualPeerRoutes": _manual_peer_routes_payload(),
            "state": state_payload(),
        })

    @app.post("/api/peer-routes/refresh")
    def api_refresh_peer_routes() -> Response:
        _refresh_manual_peer_routes(force=True)
        return jsonify({
            "ok": True,
            "message": "Direkte NAT-/DDNS-Endpunkte geprüft.",
            "manualPeerRoutes": _manual_peer_routes_payload(),
            "state": state_payload(),
        })

    @app.post("/api/peers/disable")
    def api_disable_peer() -> Response:
        payload = request.get_json(silent=True) if request.is_json else request.form
        peer_id = _safe_peer_id(str((payload or {}).get("peer_id") or ""))
        if not peer_id:
            return jsonify({"ok": False, "message": "peer_id fehlt", "state": state_payload()}), 400
        if peer_id == identity.node_id:
            return jsonify({"ok": False, "message": "Der eigene Knoten kann nicht deaktiviert werden", "state": state_payload()}), 400
        peer = peer_provider.get_peer(peer_id)
        try:
            _disable_peer(peer_id, peer)
        except ValueError as exc:
            return jsonify({"ok": False, "message": str(exc), "state": state_payload()}), 400
        label = display_name_for_peer(peer_id, getattr(peer, "name", None))
        if peer is not None:
            try:
                label = str(peer.to_dict().get("display_name") or label)
            except Exception:
                pass
        return jsonify({"ok": True, "message": f"Peer deaktiviert: {label}", "state": state_payload()})

    @app.post("/api/peers/enable")
    def api_enable_peer() -> Response:
        payload = request.get_json(silent=True) if request.is_json else request.form
        peer_id = _safe_peer_id(str((payload or {}).get("peer_id") or ""))
        if not peer_id:
            return jsonify({"ok": False, "message": "peer_id fehlt", "state": state_payload()}), 400
        removed = _enable_peer(peer_id)
        message = "Peer wird wieder zugelassen und erscheint nach dem nächsten Discovery-Signal." if removed else "Peer war nicht deaktiviert."
        return jsonify({"ok": True, "message": message, "state": state_payload()})

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

    def _fetch_chunk_through_gateway(
        digest: str,
        manifest_payload: object,
        *,
        gateway_depth: int = 0,
    ) -> bytes | None:
        """Serve as a BitTorrent-like gateway for remote clients.

        A public/DDNS reachable peer may not have every chunk locally, but it may
        be in the same LAN as storage peers.  When a requester includes the
        signed manifest in a batch request, this node is allowed to fetch the
        missing chunk once from its direct peers, cache it locally and return it.
        That keeps remote downloads working without VPN while avoiding PHP as a
        bulk data carrier.
        """
        safe_digest = str(digest or "").strip()
        if not safe_digest:
            return None
        try:
            return chunk_store.read_stored_chunk(safe_digest)
        except StorageError:
            pass
        if gateway_depth >= 1 or not isinstance(manifest_payload, dict):
            return None
        try:
            manifest = FileManifest.from_dict(manifest_payload)
        except Exception:
            return None
        if not manifest_store.may_access(manifest, identity.node_id):
            return None
        chunk_meta = next((dict(chunk) for chunk in manifest.chunks if str(chunk.get("hash") or "") == safe_digest), None)
        if chunk_meta is None:
            return None
        requester_node_id = _effective_p2p_requester_node_id()
        active_peers = _list_active_peers()
        ranked = rank_peers_by_speed(active_peers, p2p_client) if active_peers else []
        peers_by_id = {peer.node_id: peer for peer in [*active_peers, *ranked]}
        peer_rank = {peer.node_id: index for index, peer in enumerate(ranked)}
        candidate_ids = [str(node_id) for node_id in chunk_meta.get("locations", []) if str(node_id)]
        candidate_ids.extend(peer.node_id for peer in ranked)
        candidate_ids = sorted(dict.fromkeys(candidate_ids), key=lambda node_id: peer_rank.get(node_id, 9999))
        for node_id in candidate_ids:
            if node_id in {identity.node_id, requester_node_id}:
                continue
            peer = peers_by_id.get(node_id)
            if peer is None:
                continue
            try:
                data = p2p_client.get_chunk(peer, digest=safe_digest)
                chunk_store.write_stored_chunk(
                    data,
                    original_size=int(chunk_meta.get("size") or len(data)),
                    index=int(chunk_meta.get("index") or 0),
                    compression=str(chunk_meta.get("compression")) if chunk_meta.get("compression") else None,
                    digest=safe_digest,
                )
                return data
            except StorageError:
                continue
        return None

    def _ensure_manifest_chunks_available(manifest: FileManifest, progress_callback: Any | None = None) -> None:
        discovered_peers_by_id = {peer.node_id: peer for peer in _list_active_peers()}
        all_peers = list(discovered_peers_by_id.values())
        ranked_download_peers = rank_peers_by_speed(all_peers, p2p_client) if all_peers else []
        # Prefer the ranked transfer route over the raw discovery entry.  This is
        # important for relay-discovered peers that advertise LAN candidates: the
        # ranker returns a direct clone once /healthz answers on the LAN address.
        peers_by_id = dict(discovered_peers_by_id)
        peers_by_id.update({peer.node_id: peer for peer in ranked_download_peers})
        peer_rank = {peer.node_id: index for index, peer in enumerate(ranked_download_peers)}
        tracker_candidates_by_digest: dict[str, list[str]] = defaultdict(list)
        for peer in ranked_download_peers:
            inventory = getattr(peer, "chunk_inventory", {}) or {}
            for digest in inventory.get(manifest.manifest_id, []):
                safe_digest = str(digest or "").strip()
                if safe_digest and peer.node_id not in tracker_candidates_by_digest[safe_digest]:
                    tracker_candidates_by_digest[safe_digest].append(peer.node_id)
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
        missing_lock = threading.RLock()
        peer_candidates: dict[str, list[str]] = defaultdict(list)
        peer_candidate_load: dict[str, int] = defaultdict(int)
        peer_order: list[str] = []

        for chunk in missing.values():
            digest = str(chunk["hash"])
            candidate_ids = list(tracker_candidates_by_digest.get(digest, []))
            candidate_ids.extend(str(node_id) for node_id in chunk.get("locations", []) if str(node_id))
            # If the manifest is stale, a chunk may already exist on a newer
            # mirror that is not listed yet. Try tracker/listed mirrors first,
            # then every active peer, but sort by current response time.
            candidate_ids.extend(peer.node_id for peer in ranked_download_peers)
            seen: set[str] = set()
            ordered_candidates: list[str] = []
            for node_id in sorted(candidate_ids, key=lambda value: peer_rank.get(str(value), 9999)):
                node_id = str(node_id)
                if node_id == identity.node_id or node_id in seen or node_id not in peers_by_id:
                    continue
                seen.add(node_id)
                ordered_candidates.append(node_id)
            if not ordered_candidates:
                continue
            estimated_size = int(chunk.get("stored_size") or chunk.get("size") or 1)
            # Assign each missing chunk to exactly one primary worker. This keeps
            # the download BitTorrent-like (many peers in parallel) without making
            # every peer fetch the same chunk. The single-chunk fallback below still
            # tries all candidate peers if the assigned worker cannot provide it.
            primary_node_id = min(
                ordered_candidates,
                key=lambda node_id: (peer_candidate_load[node_id], peer_rank.get(node_id, 9999)),
            )
            peer_candidates[primary_node_id].append(digest)
            peer_candidate_load[primary_node_id] += max(1, estimated_size)
        peer_order = sorted(peer_candidates, key=lambda node_id: peer_rank.get(node_id, 9999))

        def write_restored_chunk(digest: str, stored_data: bytes) -> bool:
            with missing_lock:
                chunk = chunks_by_digest.get(digest)
                if chunk is None or digest not in missing or chunk_store.chunk_path(digest).exists():
                    missing.pop(digest, None)
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
        # bytes. Keep direct/gateway blocks moderate and direct-LAN blocks
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
                    manifest=manifest,
                    gateway_depth=0,
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

        def fetch_from_peer_worker(node_id: str) -> None:
            peer = peers_by_id.get(node_id)
            if peer is None:
                return
            peer_name = peer.to_dict().get("display_name") or peer.node_id[:12]
            batch_size, batch_byte_budget, batch_timeout = batch_limits_for_peer(peer)
            with missing_lock:
                candidate_digests = [digest for digest in peer_candidates.get(node_id, []) if digest in missing]
            batch: list[str] = []
            estimated_bytes = 0
            for digest in candidate_digests:
                with missing_lock:
                    if digest not in missing:
                        continue
                    chunk = dict(missing[digest])
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

        if peer_order:
            max_workers = max(1, min(6, len(peer_order)))
            with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="dcloud-download-peer") as executor:
                futures = [executor.submit(fetch_from_peer_worker, node_id) for node_id in peer_order]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        LOG.debug("Parallel peer download worker failed", exc_info=True)

        # Conservative fallback: if a peer/server is older and does not know the
        # batch endpoint yet, still try the previous single-chunk API so mixed
        # versions keep working.
        for position, chunk in enumerate(chunks, start=1):
            digest = str(chunk["hash"])
            if digest not in missing:
                continue
            tried: set[str] = set()
            restored = False
            candidate_ids = list(tracker_candidates_by_digest.get(digest, []))
            candidate_ids.extend(str(node_id) for node_id in chunk.get("locations", []) if str(node_id))
            candidate_ids.extend(peer.node_id for peer in ranked_download_peers)
            candidate_ids = sorted(dict.fromkeys(candidate_ids), key=lambda node_id: peer_rank.get(node_id, 9999))
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


    PREVIEW_TEXT_EXTENSIONS = {".txt", ".md", ".log", ".json", ".xml", ".yml", ".yaml", ".csv"}
    PREVIEW_SHEET_EXTENSIONS = {".csv", ".xlsx", ".xlsm", ".xls", ".ods"}
    PREVIEW_INLINE_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg",
        ".pdf", ".mp3", ".wav", ".ogg", ".m4a", ".flac",
        ".mp4", ".webm", ".mov", ".m4v",
        *PREVIEW_TEXT_EXTENSIONS,
    }

    def _manifest_for_access(manifest_id: str) -> FileManifest:
        manifest = manifest_store.load(manifest_id)
        if not manifest_store.may_access(manifest, identity.node_id):
            abort(404)
        return manifest

    def _safe_preview_path(manifest: FileManifest) -> Path:
        safe_id = re.sub(r"[^a-zA-Z0-9_.-]", "_", manifest.manifest_id)[:96] or "preview"
        safe_name = secure_filename(manifest.file_name) or "preview.bin"
        preview_dir = chunk_store.tmp_dir / "previews"
        preview_dir.mkdir(parents=True, exist_ok=True)
        return preview_dir / f"{safe_id}-{safe_name}"

    def _ensure_preview_file(manifest: FileManifest) -> Path:
        output = _safe_preview_path(manifest)
        if output.exists() and output.stat().st_size == int(manifest.file_size):
            return output
        _ensure_manifest_chunks_available(manifest)
        manifest_store.restore(manifest.manifest_id, target=output)
        return output

    def _file_extension(file_name: str) -> str:
        return Path(str(file_name or "")).suffix.lower()

    def _preview_mimetype(file_name: str) -> str:
        ext = _file_extension(file_name)
        explicit = {
            ".md": "text/markdown; charset=utf-8",
            ".log": "text/plain; charset=utf-8",
            ".yaml": "text/yaml; charset=utf-8",
            ".yml": "text/yaml; charset=utf-8",
            ".csv": "text/csv; charset=utf-8",
            ".svg": "image/svg+xml",
            ".m4a": "audio/mp4",
            ".m4v": "video/mp4",
        }.get(ext)
        if explicit:
            return explicit
        guessed, _ = mimetypes.guess_type(file_name)
        return guessed or "application/octet-stream"

    def _html_page(title: str, body: str) -> Response:
        safe_title = html.escape(title or "Vorschau")
        return Response(
            "<!doctype html><html lang='de'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>{safe_title}</title>"
            "<style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f6f9ff;color:#17233a;}"
            "header{position:sticky;top:0;background:rgba(255,255,255,.92);backdrop-filter:blur(16px);border-bottom:1px solid #d7e4f7;padding:12px 16px;}"
            "h1{font-size:16px;margin:0;}main{padding:16px;}table{border-collapse:collapse;background:white;box-shadow:0 8px 28px rgba(20,54,102,.08);border-radius:12px;overflow:hidden;}"
            "td,th{border:1px solid #dbe6f7;padding:6px 9px;min-width:70px;max-width:360px;white-space:pre-wrap;vertical-align:top;font-size:13px;}"
            "th{position:sticky;top:45px;background:#eaf3ff;color:#405b7c;font-weight:800;}"
            ".note{padding:14px 16px;border:1px solid #d7e4f7;border-radius:14px;background:white;box-shadow:0 8px 28px rgba(20,54,102,.08);}"
            "pre{white-space:pre-wrap;background:white;border:1px solid #d7e4f7;border-radius:14px;padding:14px;box-shadow:0 8px 28px rgba(20,54,102,.08);overflow:auto;}"
            "</style></head><body>"
            f"<header><h1>{safe_title}</h1></header><main>{body}</main></body></html>",
            content_type="text/html; charset=utf-8",
        )

    def _read_csv_preview(path: Path, *, max_rows: int = 220, max_cols: int = 60) -> list[list[str]]:
        raw = path.read_bytes()[:2 * 1024 * 1024]
        text = raw.decode("utf-8-sig", errors="replace")
        sample = text[:4096]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except Exception:
            dialect = csv.excel
        rows: list[list[str]] = []
        for idx, row in enumerate(csv.reader(text.splitlines(), dialect)):
            if idx >= max_rows:
                break
            rows.append([str(cell) for cell in row[:max_cols]])
        return rows

    def _xlsx_column_index(ref: str) -> int:
        letters = "".join(ch for ch in ref if ch.isalpha()).upper()
        value = 0
        for char in letters:
            value = value * 26 + (ord(char) - ord("A") + 1)
        return max(value - 1, 0)

    def _read_xlsx_preview(path: Path, *, max_rows: int = 220, max_cols: int = 60) -> list[list[str]]:
        ns = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        with zipfile.ZipFile(path) as archive:
            shared: list[str] = []
            if "xl/sharedStrings.xml" in archive.namelist():
                root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
                for si in root.findall("main:si", ns):
                    texts = [node.text or "" for node in si.findall(".//main:t", ns)]
                    shared.append("".join(texts))
            sheet_name = "xl/worksheets/sheet1.xml"
            if sheet_name not in archive.namelist():
                sheets = sorted(name for name in archive.namelist() if name.startswith("xl/worksheets/sheet") and name.endswith(".xml"))
                if not sheets:
                    return []
                sheet_name = sheets[0]
            root = ET.fromstring(archive.read(sheet_name))
            rows: list[list[str]] = []
            for row_el in root.findall(".//main:sheetData/main:row", ns):
                if len(rows) >= max_rows:
                    break
                row_values = [""] * max_cols
                sequential_col = 0
                has_value = False
                for cell in row_el.findall("main:c", ns):
                    ref = str(cell.get("r") or "")
                    col = _xlsx_column_index(ref) if ref else sequential_col
                    sequential_col = col + 1
                    if col >= max_cols:
                        continue
                    cell_type = str(cell.get("t") or "")
                    value = ""
                    if cell_type == "inlineStr":
                        texts = [node.text or "" for node in cell.findall(".//main:t", ns)]
                        value = "".join(texts)
                    else:
                        v = cell.find("main:v", ns)
                        raw_value = v.text if v is not None and v.text is not None else ""
                        if cell_type == "s":
                            try:
                                value = shared[int(raw_value)]
                            except Exception:
                                value = raw_value
                        elif cell_type == "b":
                            value = "WAHR" if raw_value == "1" else "FALSCH"
                        else:
                            value = raw_value
                    if value:
                        has_value = True
                    row_values[col] = value
                if has_value or rows:
                    while row_values and row_values[-1] == "":
                        row_values.pop()
                    rows.append(row_values)
            return rows

    def _rows_to_table(rows: list[list[str]]) -> str:
        if not rows:
            return "<div class='note'>Keine darstellbaren Tabellenwerte gefunden.</div>"
        max_cols = max((len(row) for row in rows), default=0)
        header = "<tr><th>#</th>" + "".join(f"<th>{html.escape(chr(65 + idx) if idx < 26 else str(idx + 1))}</th>" for idx in range(max_cols)) + "</tr>"
        body_rows = []
        for row_index, row in enumerate(rows, start=1):
            cells = "".join(f"<td>{html.escape(str(row[col]) if col < len(row) else '')}</td>" for col in range(max_cols))
            body_rows.append(f"<tr><th>{row_index}</th>{cells}</tr>")
        return "<table>" + header + "".join(body_rows) + "</table>"

    @app.get("/preview/<manifest_id>")
    def preview_file(manifest_id: str) -> Response:
        manifest = _manifest_for_access(manifest_id)
        ext = _file_extension(manifest.file_name)
        if ext in PREVIEW_SHEET_EXTENSIONS:
            return redirect(url_for("preview_sheet", manifest_id=manifest.manifest_id))
        if ext not in PREVIEW_INLINE_EXTENSIONS:
            return _html_page(
                manifest.file_name,
                "<div class='note'>Für diesen Dateityp gibt es keine integrierte Vorschau. Bitte nutze Herunterladen.</div>",
            )
        try:
            output = _ensure_preview_file(manifest)
        except StorageError as exc:
            abort(503, str(exc))
        response = send_file(
            output,
            as_attachment=False,
            download_name=manifest.file_name,
            mimetype=_preview_mimetype(manifest.file_name),
            conditional=True,
            max_age=0,
        )
        response.headers["Content-Disposition"] = f"inline; filename={secure_filename(manifest.file_name) or 'preview'}"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/preview/<manifest_id>/sheet")
    def preview_sheet(manifest_id: str) -> Response:
        manifest = _manifest_for_access(manifest_id)
        ext = _file_extension(manifest.file_name)
        try:
            output = _ensure_preview_file(manifest)
            if ext == ".csv":
                rows = _read_csv_preview(output)
            elif ext in {".xlsx", ".xlsm"}:
                rows = _read_xlsx_preview(output)
            else:
                return _html_page(
                    manifest.file_name,
                    "<div class='note'>Dieser Tabellen-Typ kann im Browser noch nicht direkt angezeigt werden. Unterstützt sind CSV, XLSX und XLSM.</div>",
                )
        except zipfile.BadZipFile:
            return _html_page(manifest.file_name, "<div class='note'>Die Excel-Datei konnte nicht gelesen werden.</div>")
        except StorageError as exc:
            abort(503, str(exc))
        except Exception as exc:
            return _html_page(manifest.file_name, f"<div class='note'>Vorschau konnte nicht erzeugt werden: {html.escape(str(exc))}</div>")
        return _html_page(manifest.file_name, _rows_to_table(rows))

    @app.post("/api/external-links/<manifest_id>")
    def api_create_external_download_link(manifest_id: str) -> Response:
        """Create a temporary public download link for any file visible on this node.

        Incoming peer shares are allowed as well: the current node acts as a
        gateway and restores missing chunks through LAN/Public/Gateway
        routes before streaming the file to the public relay link.
        """
        try:
            manifest = manifest_store.load(manifest_id)
        except StorageError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 404
        if not manifest_store.may_access(manifest, identity.node_id):
            return jsonify({"ok": False, "message": "Keine Berechtigung für diese Datei"}), 403
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            payload = {}
        minutes = _parse_external_link_minutes(payload.get("expires_minutes") or payload.get("minutes") or request.form.get("expires_minutes"))
        now = time.time()
        expires_at = now + (minutes * 60)
        token = secrets.token_urlsafe(32)
        with external_link_lock:
            _cleanup_external_download_links(persist=False)
            external_download_links[token] = {
                "manifest_id": manifest.manifest_id,
                "file_name": manifest.file_name,
                "created_at": now,
                "expires_at": expires_at,
                "created_by": identity.node_id,
            }
            _persist_external_download_links()
        direct_link = url_for("external_download_file", token=token, _external=True)
        relay_links = []
        usable_relay_links = []
        preferred_link = direct_link
        message = f"Direkter externer Download-Link wurde für {minutes} Minute(n) erstellt."
        return jsonify(
            {
                "ok": True,
                "url": preferred_link,
                "directUrl": direct_link,
                "relayUrl": "",
                "relayLinks": [],
                "viaRelay": False,
                "token": token,
                "expiresInMinutes": minutes,
                "expiresAt": datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
                "message": message,
            }
        )

    @app.get("/external/<token>")
    def external_download_file(token: str) -> Response:
        safe_token = "".join(char for char in str(token or "") if char.isalnum() or char in "-_")
        if not safe_token or safe_token != token:
            abort(404)
        with external_link_lock:
            _cleanup_external_download_links(persist=True)
            item = dict(external_download_links.get(safe_token) or {})
        if not item:
            abort(410, "Dieser Download-Link ist abgelaufen oder ungültig")
        if float(item.get("expires_at") or 0) <= time.time():
            with external_link_lock:
                external_download_links.pop(safe_token, None)
                _persist_external_download_links()
            abort(410, "Dieser Download-Link ist abgelaufen")
        try:
            manifest = manifest_store.load(str(item.get("manifest_id") or ""))
        except StorageError:
            abort(404)
        if not manifest_store.may_access(manifest, identity.node_id):
            abort(403, "Keine Berechtigung für diese Datei")
        try:
            _ensure_manifest_chunks_available(manifest)
            output = manifest_store.restore(manifest.manifest_id)
        except StorageError as exc:
            abort(503, str(exc))
        return send_file(output, as_attachment=True, download_name=manifest.file_name)

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

    def _gateway_proxy_target_peer(target_node_id: str) -> Peer | None:
        target = _safe_peer_id(str(target_node_id or ""))
        if not target or target == identity.node_id:
            return None
        for peer in _list_active_peers():
            if peer.node_id == target and not getattr(peer, "route_via_node_id", None):
                return peer
        return None

    def _gateway_proxy_to_target(target_node_id: str, subpath: str) -> Response:
        target_peer = _gateway_proxy_target_peer(target_node_id)
        if target_peer is None:
            return jsonify({"ok": False, "message": "Gateway-Zielpeer ist hier aktuell nicht direkt erreichbar"}), 404
        safe_subpath = str(subpath or "").lstrip("/")
        allowed_prefixes = (
            "ping",
            "chunks/",
            "manifests",
            "manifests/",
            "files/delete",
            "replication/delegate",
        )
        if not safe_subpath or not safe_subpath.startswith(allowed_prefixes):
            return jsonify({"ok": False, "message": "Gateway-Pfad ist nicht erlaubt"}), 403
        path = "/api/p2p/" + safe_subpath
        if request.query_string:
            path_with_query = path + "?" + request.query_string.decode("ascii", errors="ignore")
        else:
            path_with_query = path
        body = request.get_data(cache=True) if request.method.upper() != "GET" else b""
        headers: dict[str, str] = {"Accept": request.headers.get("Accept", "application/json")}
        content_type = request.headers.get("Content-Type")
        if content_type:
            headers["Content-Type"] = content_type
        for key, value in request.headers.items():
            lowered = key.lower()
            if lowered.startswith("x-dcloud-chunk-") or lowered in {"x-dcloud-batch-count", "x-dcloud-pack-format"}:
                headers[key] = value
        original_requester = str(request.environ.get("dcloud.p2p_node_id") or "").strip()
        if original_requester:
            headers["X-DCloud-Gateway-Requester-Node-Id"] = original_requester
        signed_headers = p2p_client._signed_headers(request.method.upper(), path_with_query, body, headers)
        url = f"{p2p_client.api_base(target_peer)}{path_with_query}"
        req = url_request.Request(url, data=body if request.method.upper() != "GET" else None, headers=signed_headers, method=request.method.upper())
        try:
            with url_request.urlopen(req, timeout=max(8.0, p2p_client.timeout * 3)) as response:
                response_body = response.read()
                out = Response(response_body, status=int(response.status))
                content_type_out = response.headers.get("Content-Type")
                if content_type_out:
                    out.headers["Content-Type"] = content_type_out
                for header_name in ("X-DCloud-Pack-Format", "X-DCloud-Max-Chunks", "X-DCloud-Max-Payload-Bytes"):
                    value = response.headers.get(header_name)
                    if value:
                        out.headers[header_name] = value
                return out
        except url_error.HTTPError as exc:
            body = exc.read()
            out = Response(body, status=int(exc.code))
            content_type_out = exc.headers.get("Content-Type") if exc.headers else None
            if content_type_out:
                out.headers["Content-Type"] = content_type_out
            return out
        except Exception as exc:
            return jsonify({"ok": False, "message": f"Gateway-Weiterleitung fehlgeschlagen: {exc}"}), 502

    def _request_base_peer_url() -> str:
        raw = str(request.url_root or "").rstrip("/")
        try:
            return _normalize_direct_peer_url(raw)
        except ValueError:
            return raw

    def _known_peers_export_payload(requester_node_id: str = "") -> list[dict[str, Any]]:
        peers: list[dict[str, Any]] = []
        gateway_urls: list[str] = []
        for raw in [_request_base_peer_url(), *_local_peer_callback_urls()]:
            try:
                normalized = _normalize_direct_peer_url(raw)
            except ValueError:
                continue
            if normalized not in gateway_urls:
                gateway_urls.append(normalized)
        for peer in peer_provider.list_peers():
            if peer.node_id in {identity.node_id, requester_node_id}:
                continue
            if getattr(peer, "route_via_node_id", None):
                continue
            item = peer.to_dict()
            item["reachable_via_gateway"] = True
            item["gateway_node_id"] = identity.node_id
            item["gateway_display_name"] = display_name_for_peer(identity.node_id, config.node.name)
            item["gateway_public_urls"] = gateway_urls[:8]
            peers.append(item)
        return peers

    @app.post("/api/p2p/peers/connect")
    def api_p2p_peer_connect() -> Response:
        payload = request.get_json(silent=True) if request.is_json else None
        if not isinstance(payload, dict):
            return jsonify({"ok": False, "message": "Peer-Connect erwartet JSON"}), 400
        requester_node_id = str(request.environ.get("dcloud.p2p_node_id") or "").strip()
        payload_node_id = _safe_peer_id(str(payload.get("node_id") or ""))
        if not requester_node_id or payload_node_id != requester_node_id:
            return jsonify({"ok": False, "message": "Peer-Connect Node-ID stimmt nicht mit Signatur überein"}), 403
        source_ip = str(request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()
        stored_peer = _store_direct_peer_from_info(payload, source_ip=source_ip, source="peer_exchange")
        if stored_peer is None:
            return jsonify({"ok": False, "message": "Peer-Connect konnte keine Rückroute speichern"}), 400
        peers = _known_peers_export_payload(requester_node_id)
        return jsonify({
            "ok": True,
            "message": "Direct-Peer-Austausch aktiv",
            "peer": _peer_exchange_payload(),
            "peers": peers,
            "count": len(peers),
        })

    @app.get("/api/p2p/peers")
    def api_p2p_known_peers() -> Response:
        requester_node_id = str(request.environ.get("dcloud.p2p_node_id") or "").strip()
        peers = _known_peers_export_payload(requester_node_id)
        return jsonify({"ok": True, "gateway_node_id": identity.node_id, "peers": peers, "count": len(peers)})

    @app.get("/api/p2p/ping")
    def api_p2p_ping() -> Response:
        """Signed liveness/storage probe for direct and gateway-routed peers.

        /healthz only proves that the HTTP endpoint we reached is alive.  For a
        peer behind a gateway, uploads must prove that the final target behind
        the gateway is reachable before it is counted as active P2P storage.
        """
        payload = _peer_exchange_payload()
        payload.update({
            "ok": True,
            "status": "ok",
            "signed_p2p": True,
            "gateway_probe_supported": True,
        })
        return jsonify(payload)

    @app.route("/api/p2p/gateway/<target_node_id>/<path:subpath>", methods=["GET", "POST"])
    def api_p2p_gateway_proxy(target_node_id: str, subpath: str) -> Response:
        return _gateway_proxy_to_target(target_node_id, subpath)

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
        manifest_payload = payload.get("manifest") if isinstance(payload.get("manifest"), dict) else None
        try:
            gateway_depth = int(payload.get("gateway_depth") or 0)
        except (TypeError, ValueError):
            gateway_depth = 0
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
                    data = _fetch_chunk_through_gateway(digest, manifest_payload, gateway_depth=gateway_depth)
                    if data is None:
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
            manifest_payload = payload.get("manifest") if isinstance(payload.get("manifest"), dict) else None
            try:
                gateway_depth = int(payload.get("gateway_depth") or 0)
            except (TypeError, ValueError):
                gateway_depth = 0
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
                    data = _fetch_chunk_through_gateway(digest, manifest_payload, gateway_depth=gateway_depth)
                    if data is None:
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
                    validate=False,
                    sync=False,
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
                    validate=False,
                    sync=False,
                )
                stored.append(digest)
            _sync_peer_connector_settings()
            return jsonify({"ok": True, "stored": stored, "stored_count": len(stored), "state": state_payload()})
        except (ValueError, StorageError, TypeError) as exc:
            return jsonify({"ok": False, "message": str(exc), "state": state_payload()}), 400

    @app.post("/api/p2p/replication/delegate")
    def api_p2p_delegate_replication() -> Response:
        """Continue RAID fan-out on the peer that received the first copy.

        The owner/start node uploads each chunk only once to this node.  This
        endpoint then uses this node's local chunk copy as source and mirrors it
        to other active peers.
        """
        try:
            payload = request.get_json(force=True)
            if not isinstance(payload, dict):
                raise StorageError("Delegations-Payload muss ein JSON-Objekt sein")
            manifest_payload = payload.get("manifest")
            if not isinstance(manifest_payload, dict):
                raise StorageError("Delegations-Payload enthält kein Manifest")
            manifest = FileManifest.from_dict(manifest_payload)
            requester_node_id = str(request.environ.get("dcloud.p2p_node_id") or "").strip()
            exclude_ids = {str(item) for item in payload.get("exclude_node_ids", []) if str(item)}
            if requester_node_id:
                exclude_ids.add(requester_node_id)
            exclude_ids.add(identity.node_id)

            delegated_chunks: list[dict[str, Any]] = []
            local_sources = 0
            for chunk in manifest.chunks:
                entry = dict(chunk)
                digest = str(entry.get("hash") or "")
                locations = [str(node_id) for node_id in entry.get("locations", []) if str(node_id)]
                if digest and chunk_store.chunk_path(digest).exists():
                    local_sources += 1
                    if identity.node_id not in locations:
                        locations.append(identity.node_id)
                entry["locations"] = list(dict.fromkeys(locations))
                delegated_chunks.append(entry)
            if local_sources <= 0:
                raise StorageError("Dieser Peer hat noch keine lokale Kopie der zu replizierenden Chunks")

            local_manifest = _manifest_clone_with_chunks(
                manifest,
                delegated_chunks,
                placement={
                    **dict(manifest.placement or {}),
                    "strategy": "delegated_peer_replication",
                    "delegated_by": requester_node_id,
                    "delegation_primary_peer": identity.node_id,
                },
            )
            peers = [peer for peer in _eligible_storage_peers() if peer.node_id not in exclude_ids]
            result = replicate_manifest_chunks(
                manifest=local_manifest,
                chunk_store=chunk_store,
                local_node_id=identity.node_id,
                peers=peers,
                p2p_client=p2p_client,
            )
            return jsonify({
                "ok": True,
                "chunks": result.chunks,
                "targets": result.targets,
                "remote_successes": result.remote_successes,
                "remote_failures": result.remote_failures,
                "desired_replicas": result.desired_replicas,
                "replicated_chunks": result.replicated_chunks,
                "under_replicated_chunks": result.under_replicated_chunks,
                "peer_count": len(peers),
                "primary_peer_id": identity.node_id,
                "state": state_payload(),
            })
        except (ValueError, TypeError, StorageError) as exc:
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
                # Hide the manifest immediately, but keep remote chunks for the
                # recovery grace period. This gives a user up to 15 days to
                # reinstall a lost peer and import the backup token before RAID
                # copies may be hard-deleted by storage peers.
                manifest_store.delete(local_manifest.manifest_id, delete_unreferenced_chunks=False)
                removed_manifest = True

            scheduled = manifest_store.schedule_remote_chunk_deletion(
                deletion_manifest,
                retention_seconds=REMOTE_DELETE_GRACE_SECONDS,
            )
            _sync_peer_connector_settings()
            return jsonify({
                "ok": True,
                "manifest_id": deletion_manifest.manifest_id,
                "removed_manifest": removed_manifest,
                "removed_chunks": 0,
                "deferred_chunks": scheduled.get("chunk_count", 0),
                "delete_after": scheduled.get("delete_after"),
                "retention_days": int(REMOTE_DELETE_GRACE_SECONDS / 86400),
                "state": state_payload(),
            })
        except (ValueError, TypeError, StorageError) as exc:
            return jsonify({"ok": False, "message": str(exc), "state": state_payload()}), 400

    def _effective_p2p_requester_node_id() -> str:
        signed_node_id = str(request.environ.get("dcloud.p2p_node_id") or "").strip()
        gateway_requester = _safe_peer_id(str(request.headers.get("X-DCloud-Gateway-Requester-Node-Id") or ""))
        if gateway_requester and gateway_requester != signed_node_id:
            # Only honor gateway requester forwarding when the signer is a
            # currently known peer.  Direct callers cannot impersonate another
            # node just by adding this header; a gateway in the direct mesh must
            # be the signer.
            active_ids = {peer.node_id for peer in peer_provider.list_peers()}
            if signed_node_id in active_ids:
                return gateway_requester
        return signed_node_id

    @app.get("/api/p2p/manifests/shared")
    def api_p2p_shared_manifests() -> Response:
        requester_node_id = _effective_p2p_requester_node_id()
        if not requester_node_id:
            return jsonify({"ok": False, "message": "P2P requester missing"}), 403
        manifests = []
        for manifest in manifest_store.list_manifests():
            if manifest.owner_node_id == requester_node_id:
                continue
            if manifest_store.is_file_deleted(manifest.manifest_id, manifest.owner_node_id):
                continue
            if manifest_store.is_share_revoked(manifest.manifest_id, manifest.owner_node_id):
                continue
            if not manifest_store.may_access(manifest, requester_node_id):
                continue
            manifests.append(manifest.to_dict())
        return jsonify({"ok": True, "manifests": manifests, "count": len(manifests)})

    @app.get("/api/p2p/manifests/owner/<owner_node_id>")
    def api_p2p_owner_manifests(owner_node_id: str) -> Response:
        owner = str(owner_node_id or "").strip()
        if not owner:
            return jsonify({"ok": False, "message": "Owner node id missing"}), 400
        requester_node_id = _effective_p2p_requester_node_id()
        manifests = []
        for manifest in manifest_store.list_manifests():
            if manifest.owner_node_id != owner:
                continue
            if manifest_store.is_file_deleted(manifest.manifest_id, manifest.owner_node_id):
                continue
            # Owners may recover their own manifests. Other peers only receive
            # manifests that are actually shared with them, which is also what the
            # receiver-side Freigaben-sync imports.
            if requester_node_id and requester_node_id != owner and not manifest_store.may_access(manifest, requester_node_id):
                continue
            if requester_node_id and requester_node_id != owner and manifest_store.is_share_revoked(manifest.manifest_id, manifest.owner_node_id):
                continue
            manifests.append(manifest.to_dict())
        return jsonify({"ok": True, "owner_node_id": owner, "manifests": manifests, "count": len(manifests)})

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
        if not _chat_enabled():
            return jsonify({"ok": False, "message": "Chat ist auf diesem Peer deaktiviert"}), 403
        payload = request.get_json(silent=True) or {}
        from_node_id = str(payload.get("from_node_id", "")).strip()
        to_node_id = str(payload.get("to_node_id", "")).strip()
        verified_node_id = str(request.environ.get("dcloud.p2p_node_id") or "").strip()
        text = str(payload.get("text", "")).strip()
        attachment = payload.get("attachment") if isinstance(payload.get("attachment"), dict) else None
        if not from_node_id or not to_node_id or (not text and not attachment):
            return jsonify({"ok": False, "message": "Ungültige Chat-Nachricht"}), 400
        if verified_node_id and verified_node_id != from_node_id:
            return jsonify({"ok": False, "message": "Chat-Absender stimmt nicht mit P2P-Signatur überein"}), 403
        if to_node_id != identity.node_id:
            return jsonify({"ok": False, "message": "Nachricht war nicht für diesen Peer bestimmt"}), 400
        if attachment and attachment.get("kind") == "image":
            data_url = str(attachment.get("data_url", ""))
            if not data_url.startswith("data:image/") or len(data_url) > 4_500_000:
                return jsonify({"ok": False, "message": "Bildanhang ist zu groß oder ungültig"}), 400
        event = {
            "id": str(payload.get("id") or uuid4().hex),
            "from_node_id": from_node_id,
            "from_alias": _sanitize_chat_alias(payload.get("from_alias") or ""),
            "to_node_id": to_node_id,
            "text": text,
            "attachment": attachment,
            "created_at": str(payload.get("created_at") or datetime.now(timezone.utc).isoformat()),
            "received_at": datetime.now(timezone.utc).isoformat(),
            "direction": "in",
            "status": "received",
        }
        with chat_lock:
            existing_ids = {str(item.get("id")) for item in chat_messages.get(from_node_id, [])}
            if event["id"] not in existing_ids:
                chat_messages[from_node_id].append(event)
                chat_unread[from_node_id] += 1
        return jsonify({"ok": True, "message_id": event["id"], "received_at": event["received_at"]})

    @app.post("/api/p2p/chat/read-receipt")
    def p2p_chat_read_receipt() -> Response:
        if not _chat_enabled():
            return jsonify({"ok": False, "message": "Chat ist auf diesem Peer deaktiviert"}), 403
        payload = request.get_json(silent=True) or {}
        from_node_id = str(payload.get("from_node_id", "")).strip()
        to_node_id = str(payload.get("to_node_id", "")).strip()
        verified_node_id = str(request.environ.get("dcloud.p2p_node_id") or "").strip()
        if verified_node_id and verified_node_id != from_node_id:
            return jsonify({"ok": False, "message": "Lesebestätigung stimmt nicht mit P2P-Signatur überein"}), 403
        if to_node_id != identity.node_id:
            return jsonify({"ok": False, "message": "Lesebestätigung war nicht für diesen Peer bestimmt"}), 400
        raw_ids = payload.get("message_ids") if isinstance(payload.get("message_ids"), list) else []
        message_ids = {str(item) for item in raw_ids if str(item)}
        read_at = str(payload.get("read_at") or datetime.now(timezone.utc).isoformat())
        updated = 0
        with chat_lock:
            for msg in chat_messages.get(from_node_id, []):
                if msg.get("direction") == "out" and str(msg.get("id")) in message_ids:
                    msg["status"] = "read"
                    msg["read_at"] = read_at
                    updated += 1
        return jsonify({"ok": True, "updated": updated})

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
    def healthz() -> dict[str, Any]:
        stats = chunk_store.stats()
        return {
            "status": "ok",
            "node_id": identity.node_id,
            "name": config.node.name,
            "display_name": display_name_for_peer(identity.node_id, config.node.name),
            "client_type": config.node.client_type,
            "web_port": int(getattr(config.web, "port", 8787) or 8787),
            "shared_storage_bytes": int(config.storage.limit_bytes),
            "free_storage_bytes": int(stats.free_limit_bytes),
            "accepts_peer_storage": True,
            "public_urls": _configured_public_peer_urls(),
            "callback_urls": _local_peer_callback_urls(),
            "relay_data_enabled": False,
            "relay_removed": True,
            "direct_peer": True,
            "peer_exchange": True,
            "gateway_discovery": True,
            "gateway_proxy": True,
        }

    app.config["DCLOUD_STOP_RELAYS"] = _stop_relay_transport
    _configure_relay_transport()
    atexit.register(_stop_relay_transport)
    return app
