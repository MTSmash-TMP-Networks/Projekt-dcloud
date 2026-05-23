"""HTTP/PHP relay transport for peers that cannot reach each other directly.

The relay is intentionally simple: clients register a heartbeat and exchange
short-lived request/response envelopes through a PHP mailbox. It is not a real
UDP TURN server; it is an HTTP proxy/relay path for dcloud's existing peer API.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import json
import logging
import re
import threading
import time
from typing import Any, Callable
from urllib import error, request
from uuid import uuid4

from .peers import Peer, PeerProvider
from ..identity import NodeIdentity

LOG = logging.getLogger(__name__)
RELAY_HOST = "__relay__"


def normalize_relay_url(value: object) -> str:
    url = str(value or "").strip().rstrip("/")
    if not url or not re.match(r"^https?://", url, flags=re.IGNORECASE):
        return ""
    return url




def relay_id_is_valid(value: object) -> bool:
    text = str(value or "").strip()
    return bool(text) and re.match(r"^[A-Za-z0-9_.:-]{1,160}$", text) is not None

def normalize_relay_urls(value: object) -> list[str]:
    if value is None:
        return []
    values: list[object]
    if isinstance(value, (list, tuple, set)):
        values = list(value)
    else:
        values = re.split(r"[\s,;]+", str(value))
    result: list[str] = []
    for item in values:
        if isinstance(item, (list, tuple, set)):
            for nested in normalize_relay_urls(item):
                if nested not in result:
                    result.append(nested)
            continue
        url = normalize_relay_url(item)
        if url and url not in result:
            result.append(url)
    return result


class RelayError(RuntimeError):
    """Raised when a relay request cannot be delivered or answered."""


def _decode_relay_json(raw: bytes, *, expected_action: str = "", expected_request_id: str = "") -> dict[str, Any]:
    """Decode a relay JSON response from shared PHP hosting.

    A correct relay returns exactly one JSON object. During upgrades or with
    stale opcache workers, some hosts have returned several JSON objects
    concatenated together. Instead of breaking uploads with ``Extra data``, parse
    all objects and select the one that matches the action/request currently in
    flight.
    """
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return {}
    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
    index = 0
    length = len(text)
    try:
        while index < length:
            while index < length and text[index].isspace():
                index += 1
            if index >= length:
                break
            parsed, next_index = decoder.raw_decode(text, index)
            if isinstance(parsed, dict):
                objects.append(parsed)
            index = next_index
    except json.JSONDecodeError as exc:
        if objects:
            LOG.warning("Relay %s returned trailing non-JSON data: %s", RELAY_HOST, text[index:index + 240])
        else:
            raise RelayError(f"Relay-Antwort ist kein gueltiges JSON: {exc}: {text[:240]}") from exc
    if not objects:
        raise RelayError("Relay-Antwort ist kein JSON-Objekt")
    if len(objects) > 1:
        LOG.warning("Relay %s returned %s JSON documents in one response; selecting the response for action %s", RELAY_HOST, len(objects), expected_action or "unknown")

    def action_matches(item: dict[str, Any]) -> bool:
        if expected_action == "health":
            return bool(item.get("ok")) and ("relay_token" in item or "version" in item)
        if expected_action == "register":
            return bool(item.get("ok")) and isinstance(item.get("peers"), list)
        if expected_action == "poll_requests":
            return bool(item.get("ok")) and isinstance(item.get("requests"), list)
        if expected_action in {"enqueue_request", "post_response"}:
            return bool(item.get("ok")) and str(item.get("request_id", "")) == expected_request_id
        if expected_action == "poll_response":
            return bool(item.get("ok")) and "ready" in item
        return bool(item.get("ok"))

    for item in objects:
        if action_matches(item):
            return item
    # Prefer a clear error over a stale ok:true document for a different action.
    for item in objects:
        if not item.get("ok", False):
            return item
    return objects[0]


@dataclass
class RelayHttpResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes


class HttpRelayClient:
    """Small JSON client for the bundled PHP relay endpoint.

    Relay access is intentionally automatic. A PHP relay publishes a short-lived
    daily access token via the public ``health`` action. The client refreshes the
    token before mailbox/register operations and retries once if a relay rotates
    while a request is in flight. ``secret`` remains as a deprecated field only
    so old configs do not break; new bundled relays ignore manual passwords.
    """

    TOKEN_REFRESH_MARGIN_SECONDS = 300

    def __init__(
        self,
        *,
        relay_url: str,
        identity: NodeIdentity,
        secret: str = "",
        timeout: float = 5.0,
        request_timeout: float = 20.0,
    ) -> None:
        self.relay_url = relay_url.rstrip("/")
        self.identity = identity
        self.secret = secret
        self.timeout = float(timeout)
        self.request_timeout = float(request_timeout)
        self.last_discovered_relay_urls: list[str] = []
        self.access_token: str = ""
        self.access_token_day: str = ""
        self.access_token_expires_at: float | None = None
        self.last_token_refresh_at: float | None = None

    def _send_json(self, payload: dict[str, Any], *, include_token: bool = True, timeout: float | None = None) -> dict[str, Any]:
        full_payload = {
            "protocol": "dcloud-relay-v1",
            "node_id": self.identity.node_id,
            # Deprecated compatibility field. New relays use relay_token.
            "secret": self.secret,
            **payload,
        }
        if include_token and self.access_token:
            full_payload["relay_token"] = self.access_token
        data = json.dumps(full_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        req = request.Request(
            self.relay_url,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout if timeout is None else timeout) as response:
                raw = response.read()
                parsed = _decode_relay_json(raw, expected_action=str(payload.get("action", "")), expected_request_id=str(payload.get("request_id", "")))
        except error.HTTPError as exc:
            message = f"HTTP {exc.code}"
            raw = b""
            try:
                raw = exc.read()
                parsed_error = _decode_relay_json(raw, expected_action=str(payload.get("action", "")), expected_request_id=str(payload.get("request_id", "")))
                if isinstance(parsed_error, dict) and parsed_error.get("message"):
                    message = str(parsed_error["message"])
            except Exception:
                text = raw.decode("utf-8", errors="replace").strip() if raw else ""
                if text:
                    message = f"HTTP {exc.code}: {text[:240]}"
            LOG.debug("Relay HTTP error for action %s via %s: %s", payload.get("action"), self.relay_url, message)
            raise RelayError(message) from exc
        except RelayError:
            raise
        except (OSError, error.URLError, json.JSONDecodeError) as exc:
            raise RelayError(f"Relay nicht erreichbar: {exc}") from exc
        if not isinstance(parsed, dict) or not parsed.get("ok", False):
            message = parsed.get("message") if isinstance(parsed, dict) else None
            raise RelayError(str(message or "Relay-Anfrage wurde abgelehnt"))
        self._remember_access_token(parsed)
        return parsed

    def _remember_access_token(self, payload: dict[str, Any]) -> None:
        token = payload.get("relay_token") or payload.get("access_token")
        if not isinstance(token, str) or not token:
            return
        self.access_token = token
        day = payload.get("relay_token_day") or payload.get("token_day")
        self.access_token_day = str(day or "")
        expires = payload.get("relay_token_expires_at") or payload.get("token_expires_at")
        try:
            self.access_token_expires_at = float(expires) if expires is not None else None
        except (TypeError, ValueError):
            self.access_token_expires_at = None
        self.last_token_refresh_at = time.time()

    def _access_token_needs_refresh(self) -> bool:
        if not self.access_token:
            return True
        if self.access_token_expires_at is None:
            return False
        return time.time() + self.TOKEN_REFRESH_MARGIN_SECONDS >= self.access_token_expires_at

    def _relay_url_with_php_suffix(self) -> str:
        if self.relay_url.lower().endswith('/dcloud_relay.php'):
            return self.relay_url
        return self.relay_url.rstrip('/') + '/dcloud_relay.php'

    def refresh_access_token(self) -> dict[str, Any]:
        """Fetch the current relay token from the relay health endpoint."""
        try:
            return self._send_json({"action": "health"}, include_token=False)
        except RelayError as exc:
            # Common deployment mistake: relay base URL is configured without
            # the actual PHP endpoint filename.
            fallback_url = self._relay_url_with_php_suffix()
            current_url = self.relay_url
            should_retry_with_suffix = fallback_url != current_url and any(
                marker in str(exc).lower()
                for marker in ("json", "404", "405", "not found")
            )
            if not should_retry_with_suffix:
                raise
            LOG.warning("Relay health failed for %s; retrying with %s", current_url, fallback_url)
            self.relay_url = fallback_url
            try:
                return self._send_json({"action": "health"}, include_token=False)
            except RelayError:
                self.relay_url = current_url
                raise

    def ensure_access_token(self) -> None:
        if self._access_token_needs_refresh():
            self.refresh_access_token()

    def token_payload(self) -> dict[str, Any]:
        """Return metadata that can be gossiped to other clients."""
        if not self.access_token:
            return {}
        return {
            "relay_url": self.relay_url,
            "relay_token": self.access_token,
            "relay_token_day": self.access_token_day,
            "relay_token_expires_at": self.access_token_expires_at,
        }

    def _post_json(self, payload: dict[str, Any], *, timeout: float | None = None) -> dict[str, Any]:
        action = str(payload.get("action", ""))
        if action != "health":
            self.ensure_access_token()
        try:
            return self._send_json(payload, include_token=action != "health", timeout=timeout)
        except RelayError as exc:
            # A relay may rotate its daily token between register/poll cycles.
            # Refresh once and retry instead of showing a confusing error.
            token_error = "token" in str(exc).lower() or "tages" in str(exc).lower()
            if action != "health" and token_error:
                self.refresh_access_token()
                return self._send_json(payload, include_token=True, timeout=timeout)
            raise

    def health(self) -> dict[str, Any]:
        return self._post_json({"action": "health"})

    def register(self, metadata: dict[str, Any], *, peer_timeout_seconds: int = 35) -> list[Peer]:
        safe_metadata = metadata if isinstance(metadata, dict) else {}
        payload = self._post_json(
            {
                "action": "register",
                "peer": safe_metadata,
                "peer_timeout_seconds": int(peer_timeout_seconds),
            }
        )
        raw_peers = payload.get("peers", [])
        discovered_relays: list[str] = []
        peers: list[Peer] = []
        if isinstance(raw_peers, list):
            for raw in raw_peers:
                if isinstance(raw, dict):
                    discovered_relays.extend(normalize_relay_urls(raw.get("relay_urls")))
                    discovered_relays.extend(normalize_relay_urls(raw.get("relay_url")))
                peer = peer_from_relay_payload(raw, relay_url=self.relay_url, own_node_id=self.identity.node_id)
                if peer is not None:
                    peers.append(peer)
        discovered_relays.extend(normalize_relay_urls(payload.get("relay_urls")))
        self.last_discovered_relay_urls = [url for url in normalize_relay_urls(discovered_relays) if url != self.relay_url]
        return peers

    def poll_requests(self, *, max_requests: int = 5, wait_seconds: float = 0.0) -> list[dict[str, Any]]:
        payload = self._post_json(
            {"action": "poll_requests", "max_requests": int(max_requests), "wait_seconds": max(0.0, float(wait_seconds))},
            timeout=max(self.timeout, float(wait_seconds) + 2.0),
        )
        requests = payload.get("requests", [])
        return [item for item in requests if isinstance(item, dict)] if isinstance(requests, list) else []

    def post_response(self, request_id: str, response: RelayHttpResponse) -> None:
        headers = {str(key): str(value) for key, value in (response.headers or {}).items()}
        self._post_json(
            {
                "action": "post_response",
                "request_id": str(request_id),
                "relay_request_id": str(request_id),
                "status_code": int(response.status_code),
                "headers": headers,
                "body_base64": base64.b64encode(response.body).decode("ascii"),
            },
            timeout=max(self.timeout, min(self.request_timeout, 12.0)),
        )

    def forward_request(
        self,
        peer: Peer,
        *,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        timeout: float | None = None,
    ) -> RelayHttpResponse:
        if not peer.relay_url:
            raise RelayError("Peer hat keine Relay-Route")
        if peer.relay_url.rstrip("/") != self.relay_url:
            raise RelayError("Peer nutzt einen anderen Relay-Server")
        if not relay_id_is_valid(peer.node_id):
            raise RelayError(f"Peer hat keine gueltige Node-ID: {str(peer.node_id or '')[:24]}")
        if method.upper() not in {"GET", "POST"} or not path.startswith("/api/p2p/"):
            raise RelayError("Ungueltige Relay-Anfrage")
        request_id = uuid4().hex
        if not relay_id_is_valid(request_id):
            raise RelayError("Interne Relay-request_id ist ungueltig")
        wait_timeout = float(timeout if timeout is not None else self.request_timeout)
        # Include both the canonical and compatibility field names. Older PHP
        # relay revisions and some cached OPcache workers may understand only
        # one spelling; sending both is harmless and avoids empty target queues.
        self._post_json(
            {
                "action": "enqueue_request",
                "request_id": request_id,
                "relay_request_id": request_id,
                "to_node_id": str(peer.node_id),
                "target_node_id": str(peer.node_id),
                "method": method.upper(),
                "path": path,
                "headers": {str(key): str(value) for key, value in (headers or {}).items()},
                "body_base64": base64.b64encode(body).decode("ascii"),
            },
            timeout=max(self.timeout, min(wait_timeout, 30.0)),
        )
        deadline = time.monotonic() + wait_timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                wait_seconds = min(3.0, max(0.5, deadline - time.monotonic()))
                payload = self._post_json(
                    {"action": "poll_response", "request_id": request_id, "relay_request_id": request_id, "wait_seconds": wait_seconds},
                    timeout=max(self.timeout, wait_seconds + 2.0),
                )
                if payload.get("ready"):
                    response = payload.get("response", {})
                    if not isinstance(response, dict):
                        raise RelayError("Relay-Antwort ist ungültig")
                    try:
                        body_bytes = base64.b64decode(str(response.get("body_base64", "")))
                    except Exception as exc:
                        raise RelayError("Relay-Antwort enthält ungültige Nutzdaten") from exc
                    raw_headers = response.get("headers", {})
                    headers_out = {str(k): str(v) for k, v in raw_headers.items()} if isinstance(raw_headers, dict) else {}
                    return RelayHttpResponse(
                        status_code=int(response.get("status_code", 502)),
                        headers=headers_out,
                        body=body_bytes,
                    )
            except RelayError as exc:
                last_error = exc
            time.sleep(0.1)
        if last_error is not None:
            raise RelayError(f"Relay-Transfer ohne Antwort: {last_error}") from last_error
        raise RelayError("Relay-Transfer ohne Antwort")

def peer_from_relay_payload(raw: object, *, relay_url: str, own_node_id: str | None = None) -> Peer | None:
    if not isinstance(raw, dict):
        return None
    node_id = str(raw.get("node_id", "")).strip()
    if not node_id or node_id == own_node_id:
        return None
    try:
        udp_port = int(raw.get("udp_port") or 0)
    except (TypeError, ValueError):
        udp_port = 0
    def optional_int(key: str) -> int | None:
        try:
            value = raw.get(key)
            return int(value) if value is not None and str(value) != "" else None
        except (TypeError, ValueError):
            return None
    client_type = str(raw.get("client_type")) if raw.get("client_type") in {"server"} else None
    return Peer(
        node_id=node_id,
        host=RELAY_HOST,
        udp_port=udp_port,
        name=str(raw.get("name")) if raw.get("name") else None,
        client_type=client_type,
        shared_storage_bytes=optional_int("shared_storage_bytes"),
        accepts_peer_storage=bool(raw.get("accepts_peer_storage")) if "accepts_peer_storage" in raw else None,
        web_port=optional_int("web_port"),
        free_storage_bytes=optional_int("free_storage_bytes"),
        relay_url=relay_url.rstrip("/"),
        public_ip=str(raw.get("public_ip") or raw.get("remote_addr") or "").strip() or None,
    )


class HttpRelayTransport:
    """Background relay registration, peer discovery and mailbox worker."""

    def __init__(
        self,
        *,
        relay_client: HttpRelayClient,
        identity: NodeIdentity,
        node_name: str,
        peer_provider: PeerProvider,
        dispatcher: Callable[[dict[str, Any]], RelayHttpResponse],
        protocol_magic: str,
        udp_port: int = 0,
        web_port: int | None = None,
        client_type: str = "server",
        shared_storage_bytes: int = 0,
        free_storage_bytes: int = 0,
        accepts_peer_storage: bool = False,
        poll_interval_seconds: float = 1.0,
        peer_timeout_seconds: int = 35,
        relay_urls: list[str] | None = None,
        relay_discovery_callback: Callable[[list[str]], None] | None = None,
    ) -> None:
        self.relay_client = relay_client
        self.relay_url = relay_client.relay_url
        self.identity = identity
        self.node_name = node_name
        self.peer_provider = peer_provider
        self.dispatcher = dispatcher
        self.protocol_magic = protocol_magic
        self.udp_port = int(udp_port or 0)
        self.web_port = web_port
        self.client_type = client_type
        self.shared_storage_bytes = int(shared_storage_bytes)
        self.free_storage_bytes = int(free_storage_bytes)
        self.accepts_peer_storage = bool(accepts_peer_storage)
        self.poll_interval_seconds = max(0.2, float(poll_interval_seconds))
        self.register_interval_seconds = max(5.0, min(30.0, float(peer_timeout_seconds) / 3.0))
        self.peer_timeout_seconds = int(peer_timeout_seconds)
        urls = normalize_relay_urls(relay_urls or [])
        if self.relay_url not in urls:
            urls.insert(0, self.relay_url)
        self.relay_urls = urls
        self.relay_discovery_callback = relay_discovery_callback
        self.last_error: str | None = None
        self.last_success_at: float | None = None
        self.active_request_workers = 0
        # Relay-dispatched peer requests must not block mailbox polling. On
        # slow PHP/FastCGI hosts a response POST can stall for several seconds;
        # handling envelopes in small worker threads keeps the receiver polling
        # and prevents uploads from freezing mid-file.
        self.max_request_workers = 4
        self._worker_lock = threading.Lock()
        self._worker_slots = threading.BoundedSemaphore(self.max_request_workers)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="http-relay", daemon=True)
        self._thread.start()
        LOG.info("HTTP relay enabled via %s", self.relay_url)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=0.2)
        self._thread = None

    def announce_once(self) -> None:
        self._register_and_ingest_peers()
        self._poll_and_process_requests()

    def prune_stale_peers(self) -> list[str]:
        purge = getattr(self.peer_provider, "purge_stale", None)
        if not callable(purge):
            return []
        removed = list(purge())
        return [peer.node_id for peer in removed]

    def _loop(self) -> None:
        """Keep the relay mailbox warm without delaying chunk requests.

        Older versions registered and then slept for the full poll interval on
        every cycle. Over a PHP relay this added one to two seconds of latency
        per chunk because the receiving client was not always waiting in
        ``poll_requests`` when the sender enqueued a chunk. This loop registers
        only periodically and otherwise stays in long-poll mode so requests are
        picked up almost immediately.
        """
        next_register_at = 0.0
        while not self._stop_event.is_set():
            try:
                now = time.monotonic()
                if now >= next_register_at:
                    self._register_and_ingest_peers()
                    next_register_at = now + self.register_interval_seconds
                self._poll_and_process_requests()
                self.last_error = None
                self.last_success_at = time.time()
            except Exception as exc:
                self.last_error = str(exc)
                LOG.debug("HTTP relay loop failed", exc_info=True)
                self._stop_event.wait(self.poll_interval_seconds)

    def _metadata(self) -> dict[str, Any]:
        token_payload = self.relay_client.token_payload()
        relay_tokens = [token_payload] if token_payload else []
        return {
            "node_id": self.identity.node_id,
            "public_key": self.identity.public_key_b64,
            "name": self.node_name,
            "udp_port": self.udp_port,
            "web_port": self.web_port,
            "protocol_magic": self.protocol_magic,
            "client_type": self.client_type,
            "shared_storage_bytes": self.shared_storage_bytes,
            "free_storage_bytes": self.free_storage_bytes,
            "accepts_peer_storage": self.accepts_peer_storage,
            "relay_url": self.relay_url,
            "relay_urls": self.relay_urls,
            # Distributed as metadata so clients can see which relay day-token a
            # peer currently uses. Clients can always refresh directly via the
            # relay health action; this is gossip metadata, not a user setting.
            "relay_tokens": relay_tokens,
            "timestamp": int(time.time()),
        }

    def _register_and_ingest_peers(self) -> None:
        self.relay_client.ensure_access_token()
        peers = self.relay_client.register(self._metadata(), peer_timeout_seconds=self.peer_timeout_seconds)
        for peer in peers:
            self.peer_provider.add_or_update(peer)
        if self.relay_client.last_discovered_relay_urls and self.relay_discovery_callback is not None:
            self.relay_discovery_callback(self.relay_client.last_discovered_relay_urls)

    def _handle_relay_envelope(self, envelope: dict[str, Any]) -> None:
        request_id = str(envelope.get("request_id", ""))
        if not request_id:
            return
        with self._worker_lock:
            self.active_request_workers += 1
        try:
            try:
                response = self.dispatcher(envelope)
            except Exception as exc:
                LOG.debug("Relay-dispatched local request failed", exc_info=True)
                response = RelayHttpResponse(
                    status_code=500,
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"ok": False, "message": str(exc)}, sort_keys=True).encode("utf-8"),
                )
            try:
                self.relay_client.post_response(request_id, response)
            except RelayError:
                LOG.debug("Posting relay response failed", exc_info=True)
        finally:
            with self._worker_lock:
                self.active_request_workers = max(0, self.active_request_workers - 1)
            try:
                self._worker_slots.release()
            except ValueError:
                pass

    def _poll_and_process_requests(self) -> None:
        for envelope in self.relay_client.poll_requests(max_requests=16, wait_seconds=5.0):
            request_id = str(envelope.get("request_id", ""))
            if not request_id:
                continue
            if self._worker_slots.acquire(blocking=False):
                worker = threading.Thread(
                    target=self._handle_relay_envelope,
                    args=(envelope,),
                    name=f"http-relay-request-{request_id[:8]}",
                    daemon=True,
                )
                worker.start()
            else:
                # If all slots are busy, process the envelope inline instead of
                # dropping it. This is rare and still safer than losing a queued
                # chunk request.
                self._handle_relay_envelope(envelope)
