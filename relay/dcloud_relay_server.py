#!/usr/bin/env python3
"""dcloud HTTP relay server (Python alternative to dcloud_relay.php).

Run on a small VPS/Plesk Python app when PHP relay performance is not enough:

    python3 dcloud_relay_server.py --host 0.0.0.0 --port 8788

Then point a reverse proxy/domain to that port and use the public URL as an
additional relay in dcloud settings. This script uses only the Python standard
library and the same JSON protocol as relay/dcloud_relay.php.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

VERSION = "py-1.0.0"
TOKEN_ROTATION_SECONDS = 86400
PEER_TTL_SECONDS = 45
MESSAGE_TTL_SECONDS = 900
MAX_REQUESTS_PER_POLL = 32
MAX_BODY_BYTES = 256 * 1024 * 1024

DATA_DIR = Path(os.environ.get("DCLOUD_RELAY_DATA", Path(__file__).resolve().parent / "dcloud-relay-data-python"))
LOCK = threading.RLock()


def _now() -> int:
    return int(time.time())


def _day(offset: int = 0) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(_now() + offset * TOKEN_ROTATION_SECONDS))


def _ensure_dirs() -> None:
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    (DATA_DIR / "queues").mkdir(mode=0o700, exist_ok=True)
    (DATA_DIR / "responses").mkdir(mode=0o700, exist_ok=True)


def _seed() -> str:
    _ensure_dirs()
    path = DATA_DIR / "relay-token-seed.txt"
    if not path.exists():
        path.write_text(secrets.token_hex(32), encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
    value = path.read_text(encoding="utf-8").strip()
    if len(value) < 64:
        value = secrets.token_hex(32)
        path.write_text(value, encoding="utf-8")
    return value


def _token_for_day(day: str) -> str:
    return hmac.new(_seed().encode(), f"dcloud-relay-v1|{day}".encode(), hashlib.sha256).hexdigest()


def current_token_payload() -> dict[str, Any]:
    day = _day(0)
    midnight = int(time.mktime(time.strptime(day + " 00:00:00", "%Y-%m-%d %H:%M:%S")))
    return {
        "relay_token": _token_for_day(day),
        "relay_token_day": day,
        "relay_token_expires_at": midnight + TOKEN_ROTATION_SECONDS,
        "relay_token_rotation_seconds": TOKEN_ROTATION_SECONDS,
        "relay_token_mode": "automatic-daily",
    }


def token_valid(value: str) -> bool:
    value = str(value or "").strip()
    return bool(value) and any(hmac.compare_digest(value, _token_for_day(_day(offset))) for offset in (0, -1))


def normalize_action(action: str) -> str:
    action = str(action or "").strip().lower() or "health"
    aliases = {
        "ping": "health", "status": "health",
        "announce": "register", "heartbeat": "register", "register_peer": "register", "peer_register": "register",
        "enqueue": "enqueue_request", "send_request": "enqueue_request", "proxy_request": "enqueue_request", "relay_request": "enqueue_request",
        "fetch_requests": "poll_requests", "get_requests": "poll_requests", "poll": "poll_requests", "queue_poll": "poll_requests",
        "send_response": "post_response", "relay_response": "post_response", "set_response": "post_response",
        "fetch_response": "poll_response", "get_response": "poll_response", "poll_result": "poll_response",
    }
    return aliases.get(action, action)


def valid_id(value: Any) -> bool:
    text = str(value or "")
    return 0 < len(text) <= 160 and all(ch.isalnum() or ch in "_.:-" for ch in text)


def safe_id(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not valid_id(text):
        raise ValueError(f"Ungueltige {field}")
    return text


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    tmp.replace(path)


def sanitize_urls(value: Any) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, list) else str(value).replace(",", "\n").replace(";", "\n").splitlines()
    urls: list[str] = []
    for item in items:
        url = str(item).strip().rstrip("/")
        if url.startswith(("http://", "https://")) and url not in urls:
            urls.append(url)
        if len(urls) >= 20:
            break
    return urls


def sanitize_peer(peer: Any, node_id: str) -> dict[str, Any]:
    peer = peer if isinstance(peer, dict) else {}
    relay_urls = sanitize_urls(peer.get("relay_urls", peer.get("relay_url")))
    client_type = peer.get("client_type") if peer.get("client_type") in {"server"} else None
    return {
        "node_id": node_id,
        "public_key": str(peer.get("public_key", "")),
        "name": str(peer.get("name", "dcloud-node"))[:80],
        "udp_port": max(0, min(65535, int(peer.get("udp_port") or 0))),
        "web_port": max(0, min(65535, int(peer.get("web_port") or 0))),
        "protocol_magic": str(peer.get("protocol_magic", "DCLOUD1")),
        "client_type": client_type,
        "shared_storage_bytes": max(0, int(peer.get("shared_storage_bytes") or 0)),
        "free_storage_bytes": max(0, int(peer.get("free_storage_bytes") or 0)),
        "accepts_peer_storage": bool(peer.get("accepts_peer_storage")),
        "relay_url": relay_urls[0] if relay_urls else "",
        "relay_urls": relay_urls,
        "relay_tokens": peer.get("relay_tokens", []) if isinstance(peer.get("relay_tokens"), list) else [],
        "public_ip": str(peer.get("public_ip", ""))[:80],
        "relay_seen_at": _now(),
        "via_relay": True,
    }


def queue_dir(node_id: str) -> Path:
    path = DATA_DIR / "queues" / node_id
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def response_file(request_id: str) -> Path:
    return DATA_DIR / "responses" / f"{request_id}.json"


def cleanup() -> None:
    cutoff = _now() - MESSAGE_TTL_SECONDS
    for base in (DATA_DIR / "queues", DATA_DIR / "responses"):
        if not base.exists():
            continue
        for file in base.rglob("*.json"):
            try:
                if file.stat().st_mtime < cutoff:
                    file.unlink(missing_ok=True)
            except OSError:
                pass


class Handler(BaseHTTPRequestHandler):
    server_version = "dcloud-relay-python/" + VERSION

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._json({"ok": True, "version": VERSION, "time": _now(), **current_token_payload()})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        try:
            _ensure_dirs()
            cleanup()
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length > MAX_BODY_BYTES:
                self._json({"ok": False, "message": "Relay-Nutzdaten sind zu gross", "status": 413}, 413)
                return
            raw = self.rfile.read(length) if length else b""
            data = json.loads(raw.decode("utf-8")) if raw else {}
            if not isinstance(data, dict):
                data = {}
            action = normalize_action(str(data.get("action", "health")))
            if action != "health" and not token_valid(str(data.get("relay_token") or data.get("secret") or "")):
                self._json({"ok": False, "message": "Relay-Tages-Token fehlt oder ist abgelaufen", "status": 401})
                return
            with LOCK:
                if action == "health":
                    self._json({"ok": True, "version": VERSION, "time": _now(), **current_token_payload()})
                elif action == "register":
                    self.handle_register(data)
                elif action == "enqueue_request":
                    self.handle_enqueue(data)
                elif action == "poll_requests":
                    self.handle_poll_requests(data)
                elif action == "post_response":
                    self.handle_post_response(data)
                elif action == "poll_response":
                    self.handle_poll_response(data)
                else:
                    self._json({"ok": False, "message": f"Unbekannte Relay-Aktion: {action}", "status": 400})
        except Exception as exc:
            self._json({"ok": False, "message": "Relay-Fehler: " + str(exc), "status": 500}, 500)

    def handle_register(self, data: dict[str, Any]) -> None:
        node_id = safe_id(data.get("node_id"), "node_id")
        peers_path = DATA_DIR / "peers.json"
        peers = read_json(peers_path, {})
        now = _now()
        peers = {nid: p for nid, p in peers.items() if isinstance(p, dict) and now - int(p.get("relay_seen_at") or 0) <= PEER_TTL_SECONDS}
        existing = peers.get(node_id, {}) if isinstance(peers.get(node_id), dict) else {}
        peer = sanitize_peer(data.get("peer"), node_id)
        peer["public_ip"] = str(self.client_address[0] if self.client_address else "")[:80]
        for key in ("public_key", "client_type", "shared_storage_bytes", "free_storage_bytes", "accepts_peer_storage", "relay_url", "relay_urls", "web_port", "udp_port", "public_ip"):
            if peer.get(key) in (None, "", [], 0, False) and key in existing:
                peer[key] = existing[key]
        peers[node_id] = peer
        write_json(peers_path, peers)
        active = []
        relay_urls: list[str] = []
        for nid, p in peers.items():
            if nid == node_id or not isinstance(p, dict):
                continue
            item = dict(p)
            item["relay_age_seconds"] = now - int(item.get("relay_seen_at") or now)
            active.append(item)
            for url in sanitize_urls(item.get("relay_urls", item.get("relay_url"))):
                if url not in relay_urls:
                    relay_urls.append(url)
        self._json({"ok": True, "version": VERSION, "peers": active, "relay_urls": relay_urls, **current_token_payload()})

    def handle_enqueue(self, data: dict[str, Any]) -> None:
        request_id = safe_id(data.get("request_id") or data.get("relay_request_id") or data.get("id"), "request_id")
        to_node_id = safe_id(data.get("to_node_id") or data.get("target_node_id") or data.get("recipient_node_id"), "to_node_id")
        from_node_id = safe_id(data.get("node_id") or data.get("from_node_id") or data.get("sender_node_id"), "node_id")
        method = str(data.get("method", "GET")).upper()
        path = str(data.get("path") or data.get("api_path") or "")
        if method not in {"GET", "POST"} or not path.startswith("/api/p2p/"):
            self._json({"ok": False, "message": "Nur GET/POST auf /api/p2p/ sind erlaubt", "status": 403})
            return
        body64 = str(data.get("body_base64") or data.get("body") or "")
        if len(body64) > MAX_BODY_BYTES:
            self._json({"ok": False, "message": "Relay-Nutzdaten sind zu gross", "status": 413}, 413)
            return
        envelope = {
            "request_id": request_id,
            "from_node_id": from_node_id,
            "to_node_id": to_node_id,
            "method": method,
            "path": path,
            "headers": data.get("headers") if isinstance(data.get("headers"), dict) else {},
            "body_base64": body64,
            "created_at": _now(),
        }
        write_json(queue_dir(to_node_id) / f"{int(time.time()*1000)}-{request_id}.json", envelope)
        self._json({"ok": True, "request_id": request_id, "to_node_id": to_node_id})

    def handle_poll_requests(self, data: dict[str, Any]) -> None:
        node_id = safe_id(data.get("node_id"), "node_id")
        max_requests = max(1, min(MAX_REQUESTS_PER_POLL, int(data.get("max_requests") or MAX_REQUESTS_PER_POLL)))
        wait_until = time.time() + max(0.0, min(10.0, float(data.get("wait_seconds") or 0)))
        while True:
            files = sorted(queue_dir(node_id).glob("*.json"), key=lambda p: p.stat().st_mtime if p.exists() else 0)
            requests = []
            for file in files[:max_requests]:
                payload = read_json(file, {})
                file.unlink(missing_ok=True)
                if isinstance(payload, dict) and valid_id(payload.get("request_id")):
                    requests.append(payload)
            if requests or time.time() >= wait_until:
                self._json({"ok": True, "requests": requests})
                return
            time.sleep(0.1)

    def handle_post_response(self, data: dict[str, Any]) -> None:
        request_id = safe_id(data.get("request_id") or data.get("relay_request_id") or data.get("id"), "request_id")
        response = {
            "request_id": request_id,
            "status_code": int(data.get("status_code") or 502),
            "headers": data.get("headers") if isinstance(data.get("headers"), dict) else {},
            "body_base64": str(data.get("body_base64") or ""),
            "created_at": _now(),
        }
        write_json(response_file(request_id), response)
        self._json({"ok": True, "request_id": request_id})

    def handle_poll_response(self, data: dict[str, Any]) -> None:
        request_id = safe_id(data.get("request_id") or data.get("relay_request_id") or data.get("id"), "request_id")
        wait_until = time.time() + max(0.0, min(10.0, float(data.get("wait_seconds") or 0)))
        path = response_file(request_id)
        while True:
            if path.exists():
                response = read_json(path, {})
                path.unlink(missing_ok=True)
                self._json({"ok": True, "ready": True, "response": response})
                return
            if time.time() >= wait_until:
                self._json({"ok": True, "ready": False})
                return
            time.sleep(0.1)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="dcloud Python HTTP relay")
    parser.add_argument("--host", default=os.environ.get("DCLOUD_RELAY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DCLOUD_RELAY_PORT", "8788")))
    args = parser.parse_args()
    _ensure_dirs()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"dcloud Python relay {VERSION} listening on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
