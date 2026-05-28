"""HTTP-based peer storage transfer helpers.

Discovery still happens over UDP port 6881. Once peers know each other, chunk
payloads are moved over the local Flask HTTP API because real chunks can be much
larger than one safe UDP datagram.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import base64
import json
import logging
import secrets
import time
from typing import Any, Callable, Mapping
from urllib import error, parse, request

from .http_relay import RelayError, RelayHttpResponse, HttpRelayClient, RELAY_HOST
from .peers import Peer
from ..crypto import b64decode, derive_node_id, sha256_hex, sign_bytes, verify_signature
from ..identity import NodeIdentity
from ..manifests import FileManifest, canonical_manifest_bytes
from ..storage import ChunkStore, StorageError

LOG = logging.getLogger(__name__)
REVOCATION_ACTION = "revoke_share"
FILE_DELETE_ACTION = "delete_file"
DEFAULT_MIN_REPLICAS_WITH_PEERS = 2
# RAID-1-style dynamic mirror policy. 1 local/primary copy + up to three
# active peer mirrors keeps safety high without exploding storage on large meshes.
DEFAULT_MAX_DYNAMIC_REPLICAS = 4
DEFAULT_CHUNK_BATCH_SIZE = 32
# Download pack format.
CHUNK_PACK_MAGIC = b"DCLOUD-CHUNK-PACK-1\n"
# Upload pack format used for fast post-upload replication.  The peer API
# writes many chunks from one binary request instead of one HTTP/PHP request per chunk.
CHUNK_UPLOAD_PACK_MAGIC = b"DCLOUD-CHUNK-UPLOAD-PACK-1\n"
MAX_DIRECT_UPLOAD_PACK_BYTES = 64 * 1024 * 1024
MAX_RELAY_UPLOAD_PACK_BYTES = 4 * 1024 * 1024
MAX_DIRECT_UPLOAD_PACK_CHUNKS = 64
MAX_RELAY_UPLOAD_PACK_CHUNKS = 8


@dataclass
class PeerTransferResult:
    node_id: str
    ok: bool
    message: str = ""


@dataclass
class DistributedUploadResult:
    chunks: list[dict[str, Any]] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    remote_successes: int = 0
    remote_failures: int = 0
    local_chunks: int = 0
    compressed_chunks: int = 0
    raw_bytes: int = 0
    stored_bytes: int = 0
    desired_replicas: int = 1
    replicated_chunks: int = 0
    under_replicated_chunks: int = 0

    @property
    def transfer_status(self) -> str:
        if self.under_replicated_chunks and self.remote_successes:
            return "partially_replicated"
        if self.remote_failures and self.remote_successes:
            return "partial_local_fallback"
        if self.remote_failures and not self.remote_successes:
            return "local_fallback"
        if self.remote_successes:
            return "stored_on_peers"
        return "local_only"


def _direct_peer_candidates(peer: Peer) -> list[Peer]:
    """Return direct HTTP routes to probe before PHP relay fallback.

    A peer learned through the PHP relay may still be on the same LAN.  Newer
    nodes advertise LAN address candidates in their relay heartbeat; transfers
    clone the peer with each candidate host and health-check those direct routes
    before using the relay mailbox/forwarder.
    """
    candidates: list[Peer] = []
    seen: set[str] = set()

    def add(host: object) -> None:
        value = str(host or "").strip().strip("[]")
        if not value or value == RELAY_HOST or value in seen:
            return
        seen.add(value)
        candidates.append(replace(peer, host=value, route_via_node_id=None))

    # Prefer LAN candidates before public routes.  A peer learned through the
    # relay may still be in the same subnet, and local HTTP is much faster than
    # routing bulk upload/download data through PHP.
    for address in getattr(peer, "lan_addresses", []) or []:
        add(address)

    # If the peer has a manually configured public URL/DDNS/port-forward route,
    # try it before the PHP mailbox. This supports routers where the external
    # port differs from the local dcloud web_port.
    for public_url in getattr(peer, "public_urls", []) or []:
        try:
            parsed = parse.urlparse(str(public_url))
            if parsed.hostname:
                candidate = replace(
                    peer,
                    host=parsed.hostname.strip("[]"),
                    web_port=parsed.port or (443 if parsed.scheme == "https" else 80),
                    route_via_node_id=None,
                )
                add(candidate.host)
                if candidates:
                    candidates[-1] = candidate
        except Exception:
            continue

    public_host = str(getattr(peer, "public_host", "") or "").strip().strip("[]")
    if public_host:
        try:
            public_port = int(getattr(peer, "public_port", 0) or getattr(peer, "web_port", 0) or 0)
        except (TypeError, ValueError):
            public_port = 0
        candidate = replace(peer, host=public_host, web_port=public_port or peer.web_port, route_via_node_id=None)
        add(candidate.host)
        if candidates:
            candidates[-1] = candidate

    # If the peer has a port-forward-like public route and was discovered
    # through the relay, try the relay-observed public IP directly before using
    # the PHP forwarder/mailbox.
    public_ip = str(getattr(peer, "public_ip", "") or "").strip().strip("[]")
    if public_ip:
        add(public_ip)

    if peer.host != RELAY_HOST:
        add(peer.host)
    return candidates


def _relay_http_message(response: RelayHttpResponse) -> str:
    """Return a concise message for non-2xx relay-dispatched peer API replies."""
    try:
        payload = json.loads(response.body.decode("utf-8", errors="replace"))
        if isinstance(payload, dict) and payload.get("message"):
            return str(payload["message"])
    except Exception:
        pass
    text = response.body.decode("utf-8", errors="replace").strip() if response.body else ""
    if text:
        return text[:180]
    return f"Relay HTTP {response.status_code}"


def canonical_revocation_bytes(data: dict[str, Any]) -> bytes:
    """Stable bytes that are signed by the file owner for share revocations."""
    signable = {
        "action": REVOCATION_ACTION,
        "manifest_id": str(data["manifest_id"]),
        "owner_node_id": str(data["owner_node_id"]),
        "owner_public_key": str(data["owner_public_key"]),
    }
    return json.dumps(signable, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_manifest_revocation(manifest_id: str, identity: NodeIdentity) -> dict[str, Any]:
    """Create a signed revocation payload for an old shared manifest id."""
    payload: dict[str, Any] = {
        "action": REVOCATION_ACTION,
        "manifest_id": str(manifest_id),
        "owner_node_id": identity.node_id,
        "owner_public_key": identity.public_key_b64,
    }
    payload["signature"] = sign_bytes(identity.private_key, canonical_revocation_bytes(payload))
    return payload


def verify_manifest_revocation(data: dict[str, Any]) -> str:
    """Validate a signed share revocation and return the owner node id."""
    if data.get("action") != REVOCATION_ACTION:
        raise StorageError("Unsupported revocation action")
    manifest_id = str(data.get("manifest_id", ""))
    owner_node_id = str(data.get("owner_node_id", ""))
    owner_public_key = str(data.get("owner_public_key", ""))
    signature = str(data.get("signature", ""))
    if not manifest_id or not owner_node_id or not owner_public_key or not signature:
        raise StorageError("Revocation payload is incomplete")
    try:
        public_key_bytes = b64decode(owner_public_key)
    except Exception as exc:
        raise StorageError("Revocation public key is invalid") from exc
    if derive_node_id(public_key_bytes) != owner_node_id:
        raise StorageError("Revocation owner does not match public key")
    if not verify_signature(public_key_bytes, canonical_revocation_bytes(data), signature):
        raise StorageError("Revocation signature verification failed")
    return owner_node_id


def canonical_file_deletion_bytes(data: dict[str, Any]) -> bytes:
    """Stable bytes signed by the owner when a whole file is deleted.

    The full manifest is part of the signed payload. That lets storage peers
    verify that the chunk hashes they are asked to remove really belong to the
    deleted file and are not an arbitrary list supplied by another node.
    Delivery bookkeeping fields are intentionally excluded.
    """
    signable = {
        "action": FILE_DELETE_ACTION,
        "manifest_id": str(data["manifest_id"]),
        "owner_node_id": str(data["owner_node_id"]),
        "owner_public_key": str(data["owner_public_key"]),
        "manifest": data["manifest"],
    }
    return json.dumps(signable, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_manifest_deletion(manifest: FileManifest, identity: NodeIdentity) -> dict[str, Any]:
    """Create a signed payload that removes a file manifest and its chunks."""
    if manifest.owner_node_id != identity.node_id:
        raise StorageError("Only the owner can delete this manifest")
    payload: dict[str, Any] = {
        "action": FILE_DELETE_ACTION,
        "manifest_id": manifest.manifest_id,
        "owner_node_id": identity.node_id,
        "owner_public_key": identity.public_key_b64,
        "manifest": manifest.to_dict(),
    }
    payload["signature"] = sign_bytes(identity.private_key, canonical_file_deletion_bytes(payload))
    return payload


def verify_manifest_deletion(data: dict[str, Any]) -> FileManifest:
    """Validate a signed file deletion and return the manifest to remove."""
    if data.get("action") != FILE_DELETE_ACTION:
        raise StorageError("Unsupported file deletion action")
    manifest_id = str(data.get("manifest_id", ""))
    owner_node_id = str(data.get("owner_node_id", ""))
    owner_public_key = str(data.get("owner_public_key", ""))
    signature = str(data.get("signature", ""))
    manifest_payload = data.get("manifest")
    if not manifest_id or not owner_node_id or not owner_public_key or not signature or not isinstance(manifest_payload, dict):
        raise StorageError("File deletion payload is incomplete")
    try:
        public_key_bytes = b64decode(owner_public_key)
    except Exception as exc:
        raise StorageError("File deletion public key is invalid") from exc
    if derive_node_id(public_key_bytes) != owner_node_id:
        raise StorageError("File deletion owner does not match public key")
    if not verify_signature(public_key_bytes, canonical_file_deletion_bytes(data), signature):
        raise StorageError("File deletion signature verification failed")
    try:
        manifest = FileManifest.from_dict(manifest_payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise StorageError("File deletion manifest is invalid") from exc
    if manifest.manifest_id != manifest_id:
        raise StorageError("File deletion manifest id does not match payload")
    if manifest.owner_node_id != owner_node_id or manifest.owner_public_key != owner_public_key:
        raise StorageError("File deletion manifest owner does not match payload")
    if not verify_signature(public_key_bytes, canonical_manifest_bytes(manifest.to_dict()), manifest.signature):
        raise StorageError("File deletion manifest signature verification failed")
    return manifest


class P2PStorageClient:
    """Small peer API client using only the Python standard library.

    Direct LAN HTTP is attempted first. If a peer was learned through the PHP
    relay, or if direct HTTP fails while a relay fallback exists, the same peer
    API request is forwarded through the HTTP relay mailbox.
    """

    def __init__(
        self,
        *,
        timeout: float = 3.0,
        default_web_port: int = 8787,
        relay_client: HttpRelayClient | None = None,
        relay_clients: Mapping[str, HttpRelayClient] | None = None,
        identity: NodeIdentity | None = None,
    ) -> None:
        self.timeout = float(timeout)
        self.default_web_port = int(default_web_port)
        self.identity = identity
        self.relay_client = relay_client
        self.relay_clients: dict[str, HttpRelayClient] = {}
        if relay_clients:
            self.set_relay_clients(relay_clients)
        elif relay_client is not None:
            self.set_relay_clients({relay_client.relay_url: relay_client})

    def set_relay_clients(self, relay_clients: Mapping[str, HttpRelayClient] | list[HttpRelayClient]) -> None:
        if isinstance(relay_clients, list):
            clients = {client.relay_url.rstrip("/"): client for client in relay_clients}
        else:
            clients = {str(url).rstrip("/"): client for url, client in relay_clients.items()}
        self.relay_clients = clients
        self.relay_client = next(iter(clients.values()), None)

    def clear_relay_clients(self) -> None:
        self.relay_clients = {}
        self.relay_client = None

    def _signed_headers(self, method: str, path: str, body: bytes = b"", headers: dict[str, str] | None = None) -> dict[str, str]:
        out = {str(key): str(value) for key, value in (headers or {}).items()}
        if self.identity is None:
            return out
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(18)
        body_hash = sha256_hex(body or b"")
        canonical = "\n".join([method.upper(), path, timestamp, nonce, body_hash]).encode("utf-8")
        out.update({
            "X-DCloud-Node-Id": self.identity.node_id,
            "X-DCloud-Public-Key": self.identity.public_key_b64,
            "X-DCloud-Timestamp": timestamp,
            "X-DCloud-Nonce": nonce,
            "X-DCloud-Body-SHA256": body_hash,
            "X-DCloud-Signature": sign_bytes(self.identity.private_key, canonical),
        })
        return out

    def api_base(self, peer: Peer) -> str:
        host = peer.host
        # These addresses are bind addresses, not routable destinations.
        if host in {"0.0.0.0", "::", ""}:
            host = "127.0.0.1"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = int(peer.web_port or self.default_web_port)
        return f"http://{host}:{port}"

    def _relay_client_for(self, peer: Peer) -> HttpRelayClient | None:
        if not peer.relay_url:
            return None
        relay_url = peer.relay_url.rstrip("/")
        client = self.relay_clients.get(relay_url)
        if client is not None:
            return client
        if self.relay_client is not None and self.relay_client.relay_url.rstrip("/") == relay_url:
            return self.relay_client
        return None

    def _relay_available(self, peer: Peer) -> bool:
        return self._relay_client_for(peer) is not None

    def _direct_route_for_transfer(self, peer: Peer, *, timeout: float | None = None) -> Peer | None:
        """Return a currently reachable direct route for a peer, if any.

        This is intentionally used inside the low-level transfer methods, not only
        in peer ranking.  That way uploads, delegated replication requests and
        compatibility fallbacks also bypass PHP when relay-discovered peers have
        advertised LAN addresses.
        """
        probe_timeout = max(0.5, min(float(timeout if timeout is not None else self.timeout), 2.0))
        for direct_peer in _direct_peer_candidates(peer):
            try:
                url = f"{self.api_base(direct_peer)}/healthz"
                req = request.Request(url, method="GET")
                with request.urlopen(req, timeout=probe_timeout) as response:
                    if 200 <= response.status < 300:
                        return direct_peer
            except (OSError, error.URLError, error.HTTPError):
                LOG.debug("Direct transfer route for peer %s via %s failed", peer.node_id, direct_peer.host, exc_info=True)
        return None

    def _prefer_direct_transfer_peer(self, peer: Peer, *, timeout: float | None = None) -> Peer:
        return self._direct_route_for_transfer(peer, timeout=timeout) or peer

    def _forward_via_relay(
        self,
        peer: Peer,
        *,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        timeout: float | None = None,
    ) -> RelayHttpResponse:
        relay_client = self._relay_client_for(peer)
        if relay_client is None:
            raise RelayError("Relay-Client ist nicht konfiguriert")
        request_timeout = relay_client.request_timeout if timeout is None else timeout
        signed_headers = self._signed_headers(method, path, body, headers or {})

        # Fast path: let the PHP relay act as a short-lived HTTP forwarder to
        # the peer's public IP/web port. This avoids writing one mailbox file
        # per chunk on the relay. If the target is not reachable from the relay
        # server (CGNAT, firewall, no port-forward), fall back to the existing
        # mailbox relay, where the target client polls outward.
        direct_proxy_error: RelayError | None = None
        try:
            return relay_client.direct_proxy_request(
                peer,
                method=method,
                path=path,
                headers=signed_headers,
                body=body,
                timeout=request_timeout,
            )
        except RelayError as exc:
            direct_proxy_error = exc
            LOG.debug("PHP direct proxy to peer %s unavailable; falling back to mailbox relay: %s", peer.node_id, exc)

        try:
            return relay_client.forward_request(
                peer,
                method=method,
                path=path,
                headers=signed_headers,
                body=body,
                timeout=request_timeout,
            )
        except RelayError as exc:
            if direct_proxy_error is not None:
                raise RelayError(f"PHP-Forwarder fehlgeschlagen: {direct_proxy_error}; Mailbox-Relay fehlgeschlagen: {exc}") from exc
            raise

    @staticmethod
    def _relay_transfer_message(response: RelayHttpResponse, fallback: str = "stored via relay") -> str:
        mode = ""
        for key, value in (response.headers or {}).items():
            if key.lower() == "x-dcloud-relay-mode":
                mode = str(value).lower()
                break
        if mode == "direct_proxy":
            return "stored via php forwarder"
        if mode == "mailbox":
            return "stored via relay mailbox"
        return fallback

    def put_chunk(
        self,
        peer: Peer,
        *,
        digest: str,
        stored_data: bytes,
        original_size: int,
        stored_size: int,
        index: int,
        compression: str | None,
    ) -> PeerTransferResult:
        path = f"/api/p2p/chunks/{parse.quote(digest)}"
        headers = {
            "Content-Type": "application/octet-stream",
            "X-DCloud-Chunk-Original-Size": str(int(original_size)),
            "X-DCloud-Chunk-Stored-Size": str(int(stored_size)),
            "X-DCloud-Chunk-Index": str(int(index)),
        }
        if compression:
            headers["X-DCloud-Chunk-Compression"] = compression
        peer = self._prefer_direct_transfer_peer(peer)
        if peer.host != RELAY_HOST:
            url = f"{self.api_base(peer)}{path}"
            req = request.Request(url, data=stored_data, headers=self._signed_headers("POST", path, stored_data, headers), method="POST")
            try:
                with request.urlopen(req, timeout=self.timeout) as response:
                    if 200 <= response.status < 300:
                        return PeerTransferResult(peer.node_id, True, "stored")
                    return PeerTransferResult(peer.node_id, False, f"HTTP {response.status}")
            except (OSError, error.URLError, error.HTTPError) as exc:
                LOG.debug("Chunk upload to peer %s failed", peer.node_id, exc_info=True)
                if not self._relay_available(peer):
                    return PeerTransferResult(peer.node_id, False, str(exc))
        if self._relay_available(peer):
            last_error = ""
            for attempt in range(3):
                try:
                    relay_client = self._relay_client_for(peer)
                    chunk_timeout = min(float(getattr(relay_client, "request_timeout", 45.0) or 45.0), 45.0) if relay_client is not None else 45.0
                    response = self._forward_via_relay(peer, method="POST", path=path, headers=headers, body=stored_data, timeout=chunk_timeout)
                    if 200 <= response.status_code < 300:
                        suffix = "" if attempt == 0 else f" nach Retry {attempt}"
                        return PeerTransferResult(peer.node_id, True, self._relay_transfer_message(response) + suffix)
                    last_error = _relay_http_message(response)
                except RelayError as exc:
                    last_error = str(exc)
                    LOG.debug("Relay chunk upload to peer %s failed on attempt %s", peer.node_id, attempt + 1, exc_info=True)
                if attempt < 2:
                    # Relay requests are idempotent for chunks because the digest
                    # is the storage key. A retry is much cheaper than falling
                    # back locally when PHP/FastCGI answered slowly.
                    time.sleep(0.4 * (attempt + 1))
            return PeerTransferResult(peer.node_id, False, last_error or "Relay-Chunktransfer fehlgeschlagen")
        return PeerTransferResult(peer.node_id, False, "Keine erreichbare Peer-Route")

    @staticmethod
    def _encode_chunk_upload_pack(chunks: list[dict[str, Any]]) -> bytes:
        body = bytearray(CHUNK_UPLOAD_PACK_MAGIC)
        for item in chunks:
            digest = str(item["digest"])
            data = bytes(item["stored_data"])
            original_size = int(item["original_size"])
            stored_size = int(item.get("stored_size", len(data)))
            index = int(item["index"])
            compression = str(item.get("compression") or "-")
            # Keep metadata ASCII and one-line. Currently compression values are
            # short identifiers like "zlib"; a dash means no compression.
            if " " in compression or "\n" in compression or "\r" in compression:
                compression = "-"
            header = f"{digest} {original_size} {stored_size} {index} {compression}\n".encode("ascii", errors="strict")
            body.extend(header)
            body.extend(data)
        return bytes(body)

    @staticmethod
    def _decode_batch_store_response(response_body: bytes) -> set[str]:
        payload = json.loads(response_body.decode("utf-8", errors="replace"))
        stored = payload.get("stored", []) if isinstance(payload, dict) else []
        return {str(digest) for digest in stored if isinstance(digest, str)}

    def put_chunks_pack(self, peer: Peer, *, chunks: list[dict[str, Any]]) -> list[PeerTransferResult]:
        """Store multiple chunks on one peer with one binary request.

        This is the fast upload-replication path. It avoids a separate HTTP/PHP
        request for every chunk and avoids JSON/base64 inside the peer API. When
        the PHP relay/forwarder is used, the outer relay request still needs to
        encode the body, so relay batches are intentionally smaller than direct
        batches.
        """
        if not chunks:
            return []
        path = "/api/p2p/chunks/batch/pack/upload"
        data = self._encode_chunk_upload_pack(chunks)
        headers = {
            "Content-Type": "application/octet-stream",
            "Accept": "application/json",
            "X-DCloud-Batch-Count": str(len(chunks)),
            "X-DCloud-Pack-Format": "chunk-upload-pack-v1",
        }
        response_body: bytes | None = None
        direct_error: Exception | None = None
        peer = self._prefer_direct_transfer_peer(peer, timeout=2.0)
        if peer.host != RELAY_HOST:
            url = f"{self.api_base(peer)}{path}"
            req = request.Request(url, data=data, headers=self._signed_headers("POST", path, data, headers), method="POST")
            try:
                with request.urlopen(req, timeout=max(self.timeout, 45.0)) as response:
                    if 200 <= response.status < 300:
                        response_body = response.read()
                    else:
                        return [PeerTransferResult(peer.node_id, False, f"HTTP {response.status}") for _ in chunks]
            except (OSError, error.URLError, error.HTTPError) as exc:
                direct_error = exc
                LOG.debug("Binary batch chunk upload to peer %s failed", peer.node_id, exc_info=True)
                if not self._relay_available(peer):
                    return [PeerTransferResult(peer.node_id, False, str(exc)) for _ in chunks]
        if response_body is None and self._relay_available(peer):
            try:
                timeout = 60.0 if peer.host == RELAY_HOST else 45.0
                relay_response = self._forward_via_relay(peer, method="POST", path=path, headers=headers, body=data, timeout=timeout)
                if 200 <= relay_response.status_code < 300:
                    response_body = relay_response.body
                else:
                    message = _relay_http_message(relay_response)
                    return [PeerTransferResult(peer.node_id, False, message) for _ in chunks]
            except RelayError as exc:
                LOG.debug("Relay binary batch chunk upload to peer %s failed", peer.node_id, exc_info=True)
                return [PeerTransferResult(peer.node_id, False, str(exc)) for _ in chunks]
        if response_body is None:
            return [PeerTransferResult(peer.node_id, False, str(direct_error or "Keine erreichbare Peer-Route")) for _ in chunks]
        try:
            stored_digests = self._decode_batch_store_response(response_body)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
            LOG.debug("Peer %s returned invalid binary batch response", peer.node_id, exc_info=True)
            return [PeerTransferResult(peer.node_id, False, str(exc)) for _ in chunks]
        results: list[PeerTransferResult] = []
        for item in chunks:
            digest = str(item["digest"])
            if digest in stored_digests:
                results.append(PeerTransferResult(peer.node_id, True, "stored via binary batch"))
            else:
                results.append(PeerTransferResult(peer.node_id, False, f"chunk {digest[:12]} not acknowledged"))
        return results

    def put_chunks_batch(self, peer: Peer, *, chunks: list[dict[str, Any]]) -> list[PeerTransferResult]:
        if not chunks:
            return []
        path = "/api/p2p/chunks/batch"
        payload = {
            "chunks": [
                {
                    "digest": str(item["digest"]),
                    "stored_data_b64": base64.b64encode(bytes(item["stored_data"])).decode("ascii"),
                    "original_size": int(item["original_size"]),
                    "stored_size": int(item["stored_size"]),
                    "index": int(item["index"]),
                    "compression": str(item["compression"]) if item.get("compression") else None,
                }
                for item in chunks
            ]
        }
        data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        response_payload: dict[str, Any] = {}
        peer = self._prefer_direct_transfer_peer(peer, timeout=2.0)
        if peer.host != RELAY_HOST:
            url = f"{self.api_base(peer)}{path}"
            req = request.Request(url, data=data, headers=self._signed_headers("POST", path, data, headers), method="POST")
            try:
                with request.urlopen(req, timeout=max(self.timeout, 45.0)) as response:
                    if 200 <= response.status < 300:
                        response_payload = json.loads(response.read().decode("utf-8", errors="replace"))
                    else:
                        return [PeerTransferResult(peer.node_id, False, f"HTTP {response.status}") for _ in chunks]
            except (OSError, error.URLError, error.HTTPError) as exc:
                LOG.debug("Batch chunk upload to peer %s failed", peer.node_id, exc_info=True)
                if not self._relay_available(peer):
                    return [PeerTransferResult(peer.node_id, False, str(exc)) for _ in chunks]
        if not response_payload and self._relay_available(peer):
            try:
                relay_response = self._forward_via_relay(peer, method="POST", path=path, headers=headers, body=data, timeout=45.0)
                if 200 <= relay_response.status_code < 300:
                    response_payload = json.loads(relay_response.body.decode("utf-8", errors="replace"))
                else:
                    message = _relay_http_message(relay_response)
                    return [PeerTransferResult(peer.node_id, False, message) for _ in chunks]
            except RelayError as exc:
                LOG.debug("Relay batch chunk upload to peer %s failed", peer.node_id, exc_info=True)
                return [PeerTransferResult(peer.node_id, False, str(exc)) for _ in chunks]
        stored = response_payload.get("stored", []) if isinstance(response_payload, dict) else []
        stored_digests = {str(digest) for digest in stored if isinstance(digest, str)}
        results: list[PeerTransferResult] = []
        for item in chunks:
            digest = str(item["digest"])
            if digest in stored_digests:
                results.append(PeerTransferResult(peer.node_id, True, "stored via batch"))
            else:
                results.append(PeerTransferResult(peer.node_id, False, f"chunk {digest[:12]} not acknowledged"))
        return results

    def _decode_chunk_batch_response(self, response_payload: dict[str, Any]) -> dict[str, bytes]:
        raw_chunks = response_payload.get("chunks", []) if isinstance(response_payload, dict) else []
        chunks: dict[str, bytes] = {}
        if not isinstance(raw_chunks, list):
            return chunks
        for item in raw_chunks:
            if not isinstance(item, dict):
                continue
            digest = str(item.get("digest", "")).strip()
            encoded = str(item.get("stored_data_b64", ""))
            if not digest or not encoded:
                continue
            try:
                chunks[digest] = base64.b64decode(encoded.encode("ascii"), validate=True)
            except Exception:
                LOG.debug("Peer returned invalid base64 for chunk batch item %s", digest[:12])
        return chunks

    def _decode_chunk_pack_response(self, response_body: bytes) -> dict[str, bytes]:
        """Decode the binary batch format used for high-throughput downloads.

        Format:
            DCLOUD-CHUNK-PACK-1\n
            <digest> <stored-size>\n
            <stored bytes>

        Repeating the size-prefixed header lets arbitrary encrypted/compressed
        chunk bytes pass through without JSON/base64 overhead.
        """
        if not response_body.startswith(CHUNK_PACK_MAGIC):
            raise StorageError("Peer returned an invalid chunk-pack response")
        chunks: dict[str, bytes] = {}
        offset = len(CHUNK_PACK_MAGIC)
        total = len(response_body)
        while offset < total:
            line_end = response_body.find(b"\n", offset)
            if line_end < 0:
                break
            line = response_body[offset:line_end].decode("ascii", errors="strict").strip()
            offset = line_end + 1
            if not line:
                continue
            try:
                digest, size_text = line.split(" ", 1)
                size = int(size_text)
            except (ValueError, TypeError) as exc:
                raise StorageError("Peer returned a corrupt chunk-pack header") from exc
            if size < 0 or offset + size > total:
                raise StorageError("Peer returned a truncated chunk-pack body")
            chunks[digest] = response_body[offset:offset + size]
            offset += size
        return chunks

    def _get_chunks_pack(self, peer: Peer, *, data: bytes, headers: dict[str, str], timeout: float) -> dict[str, bytes]:
        path = "/api/p2p/chunks/batch/pack"
        direct_error: Exception | None = None
        pack_headers = {**headers, "Accept": "application/octet-stream"}
        peer = self._prefer_direct_transfer_peer(peer, timeout=2.0)

        if peer.host != RELAY_HOST:
            url = f"{self.api_base(peer)}{path}"
            req = request.Request(url, data=data, headers=self._signed_headers("POST", path, data, pack_headers), method="POST")
            try:
                with request.urlopen(req, timeout=timeout) as response:
                    if not 200 <= response.status < 300:
                        raise StorageError(f"Peer {peer.node_id} returned HTTP {response.status} for chunk pack")
                    return self._decode_chunk_pack_response(response.read())
            except (OSError, error.URLError, error.HTTPError, StorageError) as exc:
                direct_error = exc
                LOG.debug("Direct chunk-pack download from peer %s failed", peer.node_id, exc_info=True)

        if self._relay_available(peer):
            relay_client = self._relay_client_for(peer)
            if relay_client is not None:
                try:
                    relay_timeout = max(45.0, min(float(timeout or 60.0), 120.0))
                    response = relay_client.direct_proxy_request_raw(
                        peer, method="POST", path=path, headers=self._signed_headers("POST", path, data, pack_headers), body=data, timeout=relay_timeout
                    )
                    if 200 <= response.status_code < 300:
                        return self._decode_chunk_pack_response(response.body)
                    direct_error = StorageError(f"Peer {peer.node_id} returned relay HTTP {response.status_code} for chunk pack")
                except (RelayError, StorageError) as exc:
                    direct_error = exc
                    LOG.debug("Raw PHP chunk-pack proxy from peer %s failed", peer.node_id, exc_info=True)

        raise StorageError(f"Chunk-Pack konnte von Peer {peer.node_id} nicht geladen werden: {direct_error}") from direct_error

    def get_chunks_batch(
        self,
        peer: Peer,
        *,
        digests: list[str],
        timeout: float | None = None,
        max_chunks: int | None = None,
        max_payload_bytes: int | None = None,
        manifest: FileManifest | dict[str, Any] | None = None,
        gateway_depth: int = 0,
    ) -> dict[str, bytes]:
        """Fetch multiple stored chunks from one peer with a single peer/API call.

        Newer peers use a binary chunk-pack endpoint first. It avoids base64, so
        one larger request is usually much faster than many small chunk requests.
        The JSON/base64 endpoint and finally the old single-chunk API remain as
        compatibility fallbacks in the caller.

        The optional limits are sent to newer peers so the downloader can keep
        PHP-forwarded requests small enough to make visible progress instead of
        waiting on one huge buffered transfer.
        """
        unique_digests = list(dict.fromkeys(str(digest).strip() for digest in digests if str(digest).strip()))
        if not unique_digests:
            return {}

        payload: dict[str, Any] = {"digests": unique_digests}
        if max_chunks is not None:
            payload["max_chunks"] = max(1, int(max_chunks))
        if max_payload_bytes is not None:
            payload["max_payload_bytes"] = max(1, int(max_payload_bytes))
        if manifest is not None:
            if isinstance(manifest, FileManifest):
                payload["manifest"] = manifest.to_dict()
            elif isinstance(manifest, dict):
                payload["manifest"] = manifest
        if gateway_depth:
            payload["gateway_depth"] = max(0, int(gateway_depth))
        data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        request_timeout = timeout if timeout is not None else max(self.timeout, 90.0)

        try:
            return self._get_chunks_pack(peer, data=data, headers=headers, timeout=float(request_timeout))
        except StorageError as pack_error:
            LOG.debug("Chunk-pack fast path from peer %s failed; falling back to JSON batch: %s", peer.node_id, pack_error)
            direct_error: Exception | None = pack_error

        path = "/api/p2p/chunks/batch/download"
        peer = self._prefer_direct_transfer_peer(peer, timeout=2.0)
        if peer.host != RELAY_HOST:
            url = f"{self.api_base(peer)}{path}"
            req = request.Request(url, data=data, headers=self._signed_headers("POST", path, data, headers), method="POST")
            try:
                with request.urlopen(req, timeout=request_timeout) as response:
                    if not 200 <= response.status < 300:
                        raise StorageError(f"Peer {peer.node_id} returned HTTP {response.status} for chunk batch")
                    payload = json.loads(response.read().decode("utf-8", errors="replace"))
                    return self._decode_chunk_batch_response(payload)
            except (OSError, error.URLError, error.HTTPError, StorageError, json.JSONDecodeError) as exc:
                direct_error = exc
                LOG.debug("Direct chunk batch download from peer %s failed", peer.node_id, exc_info=True)

        if self._relay_available(peer):
            last_error: Exception | None = None
            for attempt in range(2):
                try:
                    relay_timeout = max(45.0, min(float(request_timeout or 60.0), 90.0))
                    response = self._forward_via_relay(peer, method="POST", path=path, headers=headers, body=data, timeout=relay_timeout)
                    if 200 <= response.status_code < 300:
                        payload = json.loads(response.body.decode("utf-8", errors="replace"))
                        return self._decode_chunk_batch_response(payload)
                    last_error = StorageError(f"Peer {peer.node_id} returned relay HTTP {response.status_code} for chunk batch")
                except (RelayError, json.JSONDecodeError) as exc:
                    last_error = exc
                    LOG.debug("Relay chunk batch download from peer %s failed on attempt %s", peer.node_id, attempt + 1, exc_info=True)
                if attempt == 0:
                    time.sleep(0.4)
            raise StorageError(f"Chunk-Batch konnte über Relay von Peer {peer.node_id} nicht geladen werden: {last_error}") from last_error

        raise StorageError(f"Chunk-Batch konnte von Peer {peer.node_id} nicht geladen werden: {direct_error}") from direct_error

    def get_chunk(self, peer: Peer, *, digest: str) -> bytes:
        path = f"/api/p2p/chunks/{parse.quote(digest)}"
        direct_error: Exception | None = None
        peer = self._prefer_direct_transfer_peer(peer)
        if peer.host != RELAY_HOST:
            url = f"{self.api_base(peer)}{path}"
            req = request.Request(url, headers=self._signed_headers("GET", path, b"", {"Accept": "application/octet-stream"}), method="GET")
            try:
                with request.urlopen(req, timeout=self.timeout) as response:
                    if response.status != 200:
                        raise StorageError(f"Peer {peer.node_id} returned HTTP {response.status} for chunk {digest}")
                    return response.read()
            except (OSError, error.URLError, error.HTTPError, StorageError) as exc:
                direct_error = exc
                LOG.debug("Direct chunk download from peer %s failed", peer.node_id, exc_info=True)
        if self._relay_available(peer):
            last_error: Exception | None = None
            for attempt in range(3):
                try:
                    relay_client = self._relay_client_for(peer)
                    chunk_timeout = min(float(getattr(relay_client, "request_timeout", 45.0) or 45.0), 45.0) if relay_client is not None else 45.0
                    response = self._forward_via_relay(peer, method="GET", path=path, headers={"Accept": "application/octet-stream"}, timeout=chunk_timeout)
                    if response.status_code == 200:
                        return response.body
                    last_error = StorageError(f"Peer {peer.node_id} returned relay HTTP {response.status_code} for chunk {digest}")
                except RelayError as exc:
                    last_error = exc
                    LOG.debug("Relay chunk download from peer %s failed on attempt %s", peer.node_id, attempt + 1, exc_info=True)
                if attempt < 2:
                    time.sleep(0.4 * (attempt + 1))
            raise StorageError(f"Chunk {digest} konnte über Relay von Peer {peer.node_id} nicht geladen werden: {last_error}") from last_error
        raise StorageError(f"Chunk {digest} konnte von Peer {peer.node_id} nicht geladen werden: {direct_error}") from direct_error

    def _post_json_to_peer(self, peer: Peer, *, path: str, payload: dict[str, Any], success_message: str, log_message: str) -> PeerTransferResult:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        peer = self._prefer_direct_transfer_peer(peer)
        if peer.host != RELAY_HOST:
            url = f"{self.api_base(peer)}{path}"
            req = request.Request(url, data=data, headers=self._signed_headers("POST", path, data, headers), method="POST")
            try:
                with request.urlopen(req, timeout=self.timeout) as response:
                    if 200 <= response.status < 300:
                        return PeerTransferResult(peer.node_id, True, success_message)
                    return PeerTransferResult(peer.node_id, False, f"HTTP {response.status}")
            except (OSError, error.URLError, error.HTTPError) as exc:
                LOG.debug(log_message, peer.node_id, exc_info=True)
                if not self._relay_available(peer):
                    return PeerTransferResult(peer.node_id, False, str(exc))
        if self._relay_available(peer):
            try:
                response = self._forward_via_relay(peer, method="POST", path=path, headers=headers, body=data)
                if 200 <= response.status_code < 300:
                    return PeerTransferResult(peer.node_id, True, f"{success_message} via relay")
                return PeerTransferResult(peer.node_id, False, _relay_http_message(response))
            except RelayError as exc:
                LOG.debug("Relay " + log_message, peer.node_id, exc_info=True)
                return PeerTransferResult(peer.node_id, False, str(exc))
        return PeerTransferResult(peer.node_id, False, "Keine erreichbare Peer-Route")

    def _post_json_to_peer_payload(
        self,
        peer: Peer,
        *,
        path: str,
        payload: dict[str, Any],
        timeout: float | None = None,
        log_message: str = "JSON request to peer %s failed",
    ) -> dict[str, Any]:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        request_timeout = max(float(timeout or self.timeout), self.timeout)
        direct_error: Exception | None = None
        peer = self._prefer_direct_transfer_peer(peer)

        def parse_response(body: bytes) -> dict[str, Any]:
            parsed = json.loads(body.decode("utf-8", errors="replace"))
            if not isinstance(parsed, dict):
                raise StorageError("Peer-Antwort ist kein JSON-Objekt")
            if not parsed.get("ok", False):
                raise StorageError(str(parsed.get("message") or "Peer-Anfrage fehlgeschlagen"))
            return parsed

        if peer.host != RELAY_HOST:
            url = f"{self.api_base(peer)}{path}"
            req = request.Request(url, data=data, headers=self._signed_headers("POST", path, data, headers), method="POST")
            try:
                with request.urlopen(req, timeout=request_timeout) as response:
                    body = response.read()
                    if 200 <= response.status < 300:
                        return parse_response(body)
                    raise StorageError(f"HTTP {response.status}: {body.decode('utf-8', errors='replace')[:180]}")
            except error.HTTPError as exc:
                direct_error = StorageError(f"HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')[:180]}")
                LOG.debug(log_message, peer.node_id, exc_info=True)
                if not self._relay_available(peer):
                    raise direct_error
            except (OSError, error.URLError, ValueError, TypeError, StorageError) as exc:
                direct_error = exc
                LOG.debug(log_message, peer.node_id, exc_info=True)
                if not self._relay_available(peer):
                    raise StorageError(str(exc)) from exc

        if self._relay_available(peer):
            try:
                response = self._forward_via_relay(peer, method="POST", path=path, headers=headers, body=data, timeout=request_timeout)
                if 200 <= response.status_code < 300:
                    return parse_response(response.body)
                raise StorageError(_relay_http_message(response))
            except (RelayError, ValueError, TypeError, StorageError) as exc:
                LOG.debug("Relay " + log_message, peer.node_id, exc_info=True)
                raise StorageError(str(exc)) from exc

        raise StorageError(f"Keine erreichbare Peer-Route: {direct_error}")

    def post_replication_delegation(
        self,
        peer: Peer,
        *,
        manifest: FileManifest,
        exclude_node_ids: list[str] | None = None,
        timeout: float = 180.0,
    ) -> dict[str, Any]:
        """Ask one storage peer to continue RAID replication from its local copy.

        The starter has already sent the chunks to ``peer``.  This request shifts
        the remaining fan-out work to that peer so the starter no longer uploads
        the same file data to every mirror itself.
        """
        return self._post_json_to_peer_payload(
            peer,
            path="/api/p2p/replication/delegate",
            payload={
                "manifest": manifest.to_dict(),
                "exclude_node_ids": list(dict.fromkeys(str(item) for item in (exclude_node_ids or []) if str(item))),
            },
            timeout=timeout,
            log_message="Delegated replication request to peer %s failed",
        )

    def post_manifest(self, peer: Peer, manifest: FileManifest) -> PeerTransferResult:
        return self._post_json_to_peer(
            peer,
            path="/api/p2p/manifests",
            payload=manifest.to_dict(),
            success_message="manifest shared",
            log_message="Manifest share to peer %s failed",
        )

    def get_manifests_for_owner(self, peer: Peer, owner_node_id: str) -> list[dict[str, Any]]:
        """Fetch manifests a storage peer still has for the given owner node id."""
        safe_owner = parse.quote(str(owner_node_id or ""), safe="")
        path = f"/api/p2p/manifests/owner/{safe_owner}"
        headers = {"Accept": "application/json"}
        direct_error: Exception | None = None
        peer = self._prefer_direct_transfer_peer(peer)
        if peer.host != RELAY_HOST:
            url = f"{self.api_base(peer)}{path}"
            req = request.Request(url, headers=self._signed_headers("GET", path, b"", headers), method="GET")
            try:
                with request.urlopen(req, timeout=max(self.timeout, 8.0)) as response:
                    payload = json.loads(response.read().decode("utf-8", errors="replace"))
                    manifests = payload.get("manifests", []) if isinstance(payload, dict) else []
                    return [item for item in manifests if isinstance(item, dict)]
            except (OSError, error.URLError, error.HTTPError, ValueError, TypeError) as exc:
                direct_error = exc
                LOG.debug("Direct owner manifest recovery from peer %s failed", peer.node_id, exc_info=True)
        if self._relay_available(peer):
            try:
                response = self._forward_via_relay(peer, method="GET", path=path, headers=headers, timeout=max(self.timeout, 12.0))
                if 200 <= response.status_code < 300:
                    payload = json.loads(response.body.decode("utf-8", errors="replace"))
                    manifests = payload.get("manifests", []) if isinstance(payload, dict) else []
                    return [item for item in manifests if isinstance(item, dict)]
                direct_error = StorageError(_relay_http_message(response))
            except (RelayError, ValueError, TypeError) as exc:
                direct_error = exc
                LOG.debug("Relay owner manifest recovery from peer %s failed", peer.node_id, exc_info=True)
        raise StorageError(f"Manifest-Wiederherstellung von Peer {peer.node_id} fehlgeschlagen: {direct_error}") from direct_error

    def post_manifest_revocation(self, peer: Peer, revocation: dict[str, Any]) -> PeerTransferResult:
        return self._post_json_to_peer(
            peer,
            path="/api/p2p/manifests/revoke",
            payload=revocation,
            success_message="manifest revoked",
            log_message="Manifest revocation to peer %s failed",
        )

    def post_manifest_deletion(self, peer: Peer, deletion: dict[str, Any]) -> PeerTransferResult:
        return self._post_json_to_peer(
            peer,
            path="/api/p2p/files/delete",
            payload=deletion,
            success_message="file deleted",
            log_message="File deletion to peer %s failed",
        )




def dynamic_mirror_replica_count(
    active_peer_count: int,
    *,
    min_replicas_with_peers: int = DEFAULT_MIN_REPLICAS_WITH_PEERS,
    max_replicas: int = DEFAULT_MAX_DYNAMIC_REPLICAS,
) -> int:
    """Return the current RAID-1 mirror factor for active storage peers.

    The system stays RAID-1-like: every chunk is mirrored as whole copies, not
    striped with parity.  With no peers, one local copy is the only possible
    target.  With peers, at least two copies are requested.  Additional active
    peers raise the requested mirror factor automatically, capped by
    ``DEFAULT_MAX_DYNAMIC_REPLICAS`` so a large mesh does not multiply storage
    usage without limit.
    """
    peer_count = max(0, int(active_peer_count or 0))
    if peer_count <= 0:
        return 1
    desired = max(2, int(min_replicas_with_peers or DEFAULT_MIN_REPLICAS_WITH_PEERS))
    desired = max(desired, 1 + peer_count)
    if max_replicas > 0:
        desired = min(desired, int(max_replicas))
    return min(desired, 1 + peer_count)


def _rank_peers_by_speed(peers: list[Peer], p2p_client: P2PStorageClient) -> list[Peer]:
    """Return candidates with the fastest currently responding routes first.

    Direct LAN HTTP routes are probed before relay.  Relay-discovered peers may
    advertise LAN address candidates; if one answers on ``/healthz`` we return a
    direct clone of that peer so downloads/uploads bypass PHP entirely.  Relay is
    kept only as a fallback when no direct route currently answers.
    """
    ranked: list[tuple[float, Peer]] = []
    relay_ranked: list[tuple[float, Peer]] = []

    for peer in peers:
        direct_routes = _direct_peer_candidates(peer)
        direct_matched = False
        for direct_peer in direct_routes:
            started = time.perf_counter()
            try:
                url = f"{p2p_client.api_base(direct_peer)}/healthz"
                req = request.Request(url, method="GET")
                with request.urlopen(req, timeout=max(0.75, p2p_client.timeout * 0.75)) as response:
                    if 200 <= response.status < 300:
                        ranked.append((time.perf_counter() - started, direct_peer))
                        direct_matched = True
                        break
            except (OSError, error.URLError, error.HTTPError):
                LOG.debug("Direct health check for peer %s via %s failed", peer.node_id, direct_peer.host, exc_info=True)

        if direct_matched:
            continue

        if p2p_client._relay_available(peer):  # noqa: SLF001 - same module, intentional fast-path check
            # Do not send a mailbox health request here. It would add latency to
            # every transfer start and can itself queue behind chunk traffic. The
            # actual read/write call performs relay retries if needed.
            penalty = 1.0 if peer.host == RELAY_HOST else 1.5
            relay_ranked.append((penalty, peer))

    ranked.sort(key=lambda item: item[0])
    relay_ranked.sort(key=lambda item: item[0])

    ordered: list[Peer] = []
    seen: set[str] = set()
    for _latency, peer in [*ranked, *relay_ranked]:
        if peer.node_id in seen:
            continue
        seen.add(peer.node_id)
        ordered.append(peer)
    return ordered

def rank_peers_by_speed(peers: list[Peer], p2p_client: P2PStorageClient) -> list[Peer]:
    """Public wrapper used by the web layer for download source selection."""
    return _rank_peers_by_speed(peers, p2p_client)


def _rotated_targets(targets: list[Peer | None], target_ids: list[str], start_index: int) -> list[tuple[Peer | None, str]]:
    if not targets:
        return []
    rotated: list[tuple[Peer | None, str]] = []
    seen_ids: set[str] = set()
    for offset in range(len(targets)):
        slot = (start_index + offset) % len(targets)
        node_id = target_ids[slot]
        if node_id in seen_ids:
            continue
        seen_ids.add(node_id)
        rotated.append((targets[slot], node_id))
    return rotated


def _upload_batch_limits(peer: Peer) -> tuple[int, int]:
    """Return conservative upload pack limits for this peer route."""
    if peer.host == RELAY_HOST:
        # PHP receives the outer relay request as JSON. Keep the pack below
        # common post_max_size defaults after base64 expansion.
        return MAX_RELAY_UPLOAD_PACK_CHUNKS, MAX_RELAY_UPLOAD_PACK_BYTES
    return MAX_DIRECT_UPLOAD_PACK_CHUNKS, MAX_DIRECT_UPLOAD_PACK_BYTES


def distribute_file_chunks(
    *,
    source_path,
    chunk_store: ChunkStore,
    local_node_id: str,
    peers: list[Peer],
    p2p_client: P2PStorageClient,
    min_replicas_with_peers: int = DEFAULT_MIN_REPLICAS_WITH_PEERS,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    chunk_size_bytes: int | None = None,
) -> DistributedUploadResult:
    """Read a file once, store it locally and replicate chunks in fast batches.

    The older implementation wrote every remote safety copy with one HTTP/PHP
    request per chunk. On relay routes this made uploads very slow because a file
    with hundreds of chunks also meant hundreds of round trips. The local copy is
    still written immediately, but remote replicas are now queued per peer and
    flushed as binary upload packs. If a batch fails, only the failed chunks fall
    back to smaller/legacy single writes.
    """
    effective_chunk_size = int(chunk_size_bytes or chunk_store.chunk_size)
    if effective_chunk_size <= 0:
        effective_chunk_size = chunk_store.chunk_size

    ranked_peers = _rank_peers_by_speed(peers, p2p_client) if peers else []
    targets: list[Peer | None] = [*ranked_peers, None] if ranked_peers else [None]
    target_ids = [*[peer.node_id for peer in ranked_peers], local_node_id] if ranked_peers else [local_node_id]
    desired_replicas = dynamic_mirror_replica_count(len(ranked_peers), min_replicas_with_peers=min_replicas_with_peers)

    result = DistributedUploadResult(targets=list(dict.fromkeys(target_ids)), desired_replicas=desired_replicas)
    source_size = int(source_path.stat().st_size)
    total_chunks = (source_size + effective_chunk_size - 1) // effective_chunk_size if source_size else 0

    def notify(**payload: Any) -> None:
        if progress_callback is not None:
            progress_callback(payload)

    def peer_label(peer: Peer) -> str:
        return str(peer.to_dict().get("display_name") or peer.name or peer.node_id[:12])

    pending_by_peer: dict[str, dict[str, Any]] = {}

    def queue_remote_chunk(peer: Peer, item: dict[str, Any]) -> None:
        bucket = pending_by_peer.setdefault(peer.node_id, {"peer": peer, "chunks": [], "bytes": 0})
        bucket["chunks"].append(item)
        bucket["bytes"] += int(item.get("stored_size", len(bytes(item["stored_data"]))))

    def flush_peer_bucket(node_id: str, *, reason: str = "batch") -> None:
        bucket = pending_by_peer.get(node_id)
        if not bucket or not bucket.get("chunks"):
            return
        peer: Peer = bucket["peer"]
        chunks: list[dict[str, Any]] = list(bucket["chunks"])
        pending_by_peer[node_id] = {"peer": peer, "chunks": [], "bytes": 0}
        name = peer_label(peer)
        first_index = min(int(item["entry_index"]) for item in chunks) if chunks else 0
        notify(
            phase="peer_upload_batch",
            status=f"Replikationspaket wird an {name} übertragen… +{len(chunks)} Chunks",
            current_chunk=min(first_index + len(chunks), max(total_chunks, 1)),
            total_chunks=total_chunks,
            current_peer=name,
            remote_successes=result.remote_successes,
            remote_failures=result.remote_failures,
        )

        remaining = list(chunks)
        results = p2p_client.put_chunks_pack(peer, chunks=remaining)
        if len(results) != len(remaining) or any(not transfer.ok for transfer in results):
            # Compatibility fallback: older peers may not yet expose the binary
            # upload-pack endpoint. Try the existing JSON batch before falling
            # all the way back to single-chunk writes.
            json_results = p2p_client.put_chunks_batch(peer, chunks=remaining)
            if len(json_results) == len(remaining):
                results = [json_results[i] if not results or i >= len(results) or not results[i].ok else results[i] for i in range(len(remaining))]

        for item, transfer in zip(remaining, results):
            entry = result.chunks[int(item["entry_index"])]
            if transfer.ok:
                if peer.node_id not in entry["locations"]:
                    entry["locations"].append(peer.node_id)
                result.remote_successes += 1
                continue

            result.remote_failures += 1
            # Per-chunk fallback for failed batch items. Rotate to the next peer
            # first, then retry the original peer with the legacy single API.
            stored = False
            alternate_peers = [candidate for candidate, _target_id in _rotated_targets(ranked_peers, [p.node_id for p in ranked_peers], int(item["index"]) + 1) if candidate is not None]
            fallback_candidates: list[Peer] = []
            seen_fallbacks: set[str] = set()
            for candidate in [*alternate_peers, peer]:
                if candidate.node_id in seen_fallbacks:
                    continue
                seen_fallbacks.add(candidate.node_id)
                fallback_candidates.append(candidate)
            for fallback_peer in fallback_candidates:
                if fallback_peer.node_id in entry["locations"]:
                    continue
                fallback_name = peer_label(fallback_peer)
                notify(
                    phase="peer_upload_retry",
                    status=f"Ein Chunk aus dem Paket wird kleiner an {fallback_name} wiederholt…",
                    current_chunk=int(item["index"]) + 1,
                    total_chunks=total_chunks,
                    current_peer=fallback_name,
                )
                retry = p2p_client.put_chunk(
                    fallback_peer,
                    digest=str(item["digest"]),
                    stored_data=bytes(item["stored_data"]),
                    original_size=int(item["original_size"]),
                    stored_size=int(item["stored_size"]),
                    index=int(item["index"]),
                    compression=str(item["compression"]) if item.get("compression") else None,
                )
                if retry.ok:
                    entry["locations"].append(fallback_peer.node_id)
                    result.remote_successes += 1
                    stored = True
                    break
                result.remote_failures += 1
            if not stored:
                LOG.debug("Chunk %s could not be replicated after batch failure: %s", str(item.get("digest", ""))[:12], transfer.message)

        notify(
            phase="peer_upload_batch_done",
            status=f"Replikationspaket an {name} abgeschlossen ({reason})",
            current_chunk=min(first_index + len(chunks), max(total_chunks, 1)),
            total_chunks=total_chunks,
            current_peer=name,
            remote_successes=result.remote_successes,
            remote_failures=result.remote_failures,
        )

    def flush_bucket_if_needed(peer: Peer) -> None:
        bucket = pending_by_peer.get(peer.node_id)
        if not bucket:
            return
        max_chunks, max_bytes = _upload_batch_limits(peer)
        if len(bucket["chunks"]) >= max_chunks or int(bucket["bytes"]) >= max_bytes:
            flush_peer_bucket(peer.node_id, reason="Limit erreicht")

    notify(
        phase="chunking_start",
        status="Datei wird lokal vorbereitet; Peer-Replikation wird gebündelt…",
        total_bytes=source_size,
        total_chunks=total_chunks,
        target_count=len(result.targets),
        desired_replicas=desired_replicas,
        effective_chunk_size=effective_chunk_size,
        current_chunk=0,
        raw_bytes_processed=0,
        stored_bytes=0,
        remote_successes=0,
        remote_failures=0,
        local_chunks=0,
        compressed_chunks=0,
    )

    with source_path.open("rb") as handle:
        index = 0
        local_writable = True
        while True:
            raw = handle.read(effective_chunk_size)
            if not raw:
                break
            notify(
                phase="chunk_read",
                status=f"Chunk {index + 1}/{max(total_chunks, 1)} wird vorbereitet…",
                current_chunk=index + 1,
                total_chunks=total_chunks,
                raw_bytes_processed=result.raw_bytes,
            )
            stored_data, compression = chunk_store.prepare_chunk_data(
                raw,
                file_name=getattr(source_path, "name", None),
                file_size=source_size,
            )
            digest = chunk_store.digest_for_stored_data(stored_data)
            locations: list[str] = []

            if local_writable:
                try:
                    chunk_store.write_stored_chunk(
                        stored_data,
                        original_size=len(raw),
                        index=index,
                        compression=compression,
                        digest=digest,
                        validate=False,
                    )
                    result.local_chunks += 1
                    locations.append(local_node_id)
                except StorageError as exc:
                    local_writable = False
                    notify(
                        phase="local_fallback",
                        status=f"Lokaler Speicher voll ({exc}); Upload läuft über Netzwerk-Peers weiter…",
                        current_chunk=index + 1,
                        current_peer=local_node_id,
                        local_error=str(exc),
                    )

            entry: dict[str, Any] = {
                "index": index,
                "hash": digest,
                "size": len(raw),
                "stored_size": len(stored_data),
                "locations": list(dict.fromkeys(locations)),
            }
            if compression:
                entry["compression"] = compression
                result.compressed_chunks += 1
            result.chunks.append(entry)
            result.raw_bytes += len(raw)
            result.stored_bytes += len(stored_data)

            if ranked_peers and len(entry["locations"]) < desired_replicas:
                missing_copies = max(0, desired_replicas - len(entry["locations"]))
                queued = 0
                for peer, _target_id in _rotated_targets(ranked_peers, [p.node_id for p in ranked_peers], index):
                    if peer is None or peer.node_id in entry["locations"]:
                        continue
                    name = peer_label(peer)
                    queue_remote_chunk(
                        peer,
                        {
                            "entry_index": len(result.chunks) - 1,
                            "digest": digest,
                            "stored_data": stored_data,
                            "original_size": len(raw),
                            "stored_size": len(stored_data),
                            "index": index,
                            "compression": compression,
                        },
                    )
                    queued += 1
                    notify(
                        phase="peer_upload_queued",
                        status=f"Chunk {index + 1}/{max(total_chunks, 1)} für RAID-1-Spiegel an {name} vorgemerkt…",
                        current_chunk=index + 1,
                        total_chunks=total_chunks,
                        current_peer=name,
                        raw_bytes_processed=result.raw_bytes,
                        stored_bytes=result.stored_bytes,
                        local_chunks=result.local_chunks,
                        compressed_chunks=result.compressed_chunks,
                        desired_replicas=desired_replicas,
                    )
                    flush_bucket_if_needed(peer)
                    if queued >= missing_copies:
                        break

            notify(
                phase="chunk_done",
                status=f"Chunk {index + 1}/{max(total_chunks, 1)} lokal vorbereitet",
                current_chunk=index + 1,
                total_chunks=total_chunks,
                raw_bytes_processed=result.raw_bytes,
                stored_bytes=result.stored_bytes,
                compressed_chunks=result.compressed_chunks,
                local_chunks=result.local_chunks,
                remote_successes=result.remote_successes,
                remote_failures=result.remote_failures,
            )
            index += 1

    for node_id in list(pending_by_peer):
        flush_peer_bucket(node_id, reason="Upload abgeschlossen")

    for entry in result.chunks:
        if not entry["locations"]:
            raise StorageError(
                "Kein Speicherziel verfügbar: Lokaler Speicher voll und kein erreichbarer Peer konnte den Chunk speichern"
            )
        if len(entry["locations"]) > 1:
            result.replicated_chunks += 1
        if len(entry["locations"]) < desired_replicas:
            result.under_replicated_chunks += 1

    notify(
        phase="chunking_done",
        status="Alle Chunks wurden verarbeitet; Manifest wird geschrieben…",
        current_chunk=total_chunks,
        total_chunks=total_chunks,
        raw_bytes_processed=result.raw_bytes,
        stored_bytes=result.stored_bytes,
        compressed_chunks=result.compressed_chunks,
        local_chunks=result.local_chunks,
        remote_successes=result.remote_successes,
        remote_failures=result.remote_failures,
    )
    return result


def replicate_manifest_chunks(
    *,
    manifest: FileManifest,
    chunk_store: ChunkStore,
    local_node_id: str,
    peers: list[Peer],
    p2p_client: P2PStorageClient,
    min_replicas_with_peers: int = DEFAULT_MIN_REPLICAS_WITH_PEERS,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    required_peer_node_ids: list[str] | None = None,
) -> DistributedUploadResult:
    """Replicate already-local manifest chunks to peers in the background.

    Uploads should finish as soon as the local chunks and manifest are durable.
    This helper is the asynchronous safety-copy path: it reads the stored local
    chunks, pushes them to reachable peers in binary batches and returns updated
    chunk-location metadata that the caller can re-sign into the manifest.
    """
    ranked_peers = _rank_peers_by_speed(peers, p2p_client) if peers else []
    target_ids = [*[peer.node_id for peer in ranked_peers], local_node_id] if ranked_peers else [local_node_id]
    manifest_expects_local_copy = any(
        local_node_id in [str(node_id) for node_id in chunk.get("locations", [])]
        for chunk in manifest.chunks
    )
    desired_replicas = dynamic_mirror_replica_count(len(ranked_peers), min_replicas_with_peers=min_replicas_with_peers)
    if ranked_peers and not manifest_expects_local_copy:
        # Offloaded manifests intentionally do not keep a local mirror. In that
        # mode the RAID-1 mirror factor is bounded by the active remote peers.
        desired_replicas = max(1, min(desired_replicas, len(ranked_peers)))
    required_ids = {str(node_id) for node_id in (required_peer_node_ids or []) if str(node_id)}

    result = DistributedUploadResult(
        chunks=[dict(chunk, locations=list(dict.fromkeys(str(node_id) for node_id in chunk.get("locations", []) if str(node_id)))) for chunk in manifest.chunks],
        targets=list(dict.fromkeys(target_ids)),
        desired_replicas=desired_replicas,
    )
    total_chunks = len(result.chunks)
    for entry in result.chunks:
        result.raw_bytes += int(entry.get("size", 0) or 0)
        result.stored_bytes += int(entry.get("stored_size", entry.get("size", 0)) or 0)
        if entry.get("compression"):
            result.compressed_chunks += 1
        if local_node_id in [str(node_id) for node_id in entry.get("locations", [])] and chunk_store.chunk_path(str(entry.get("hash", ""))).exists():
            result.local_chunks += 1

    def notify(**payload: Any) -> None:
        if progress_callback is not None:
            progress_callback(payload)

    def peer_label(peer: Peer) -> str:
        return str(peer.to_dict().get("display_name") or peer.name or peer.node_id[:12])

    peers_by_id = {peer.node_id: peer for peer in ranked_peers}
    active_peer_ids = set(peers_by_id)

    def healthy_locations(entry: dict[str, Any]) -> list[str]:
        """Locations that are currently usable for the dynamic RAID-1 mirror."""
        digest = str(entry.get("hash", ""))
        raw_locations = [str(node_id) for node_id in entry.get("locations", []) if str(node_id)]
        healthy: list[str] = []
        if local_node_id in raw_locations and digest and chunk_store.chunk_path(digest).exists():
            healthy.append(local_node_id)
        for node_id in raw_locations:
            if node_id != local_node_id and node_id in active_peer_ids and node_id not in healthy:
                healthy.append(node_id)
        return healthy

    def read_or_fetch_stored_data(entry: dict[str, Any]) -> bytes | None:
        """Read a local chunk, or fetch it from the fastest online mirror.

        This lets an offloaded file heal itself when one peer vanished: if one
        remaining mirror still has the chunk, this node can pull it once and
        immediately push it to a new target without requiring the user to
        download the whole file manually first.
        """
        digest = str(entry.get("hash", ""))
        if not digest:
            return None
        try:
            return chunk_store.read_stored_chunk(digest)
        except StorageError:
            pass
        source_ids = [str(node_id) for node_id in entry.get("locations", []) if str(node_id) in active_peer_ids]
        source_ids.sort(key=lambda node_id: [peer.node_id for peer in ranked_peers].index(node_id) if node_id in active_peer_ids else 9999)
        for source_id in source_ids:
            peer = peers_by_id.get(source_id)
            if peer is None:
                continue
            try:
                notify(
                    phase="background_replication_fetch_source",
                    status=f"RAID-1-Healing holt fehlenden Chunk von {peer_label(peer)}…",
                    current_chunk=int(entry.get("index", 0)) + 1,
                    total_chunks=total_chunks,
                    current_peer=peer_label(peer),
                )
                return p2p_client.get_chunk(peer, digest=digest)
            except StorageError:
                LOG.debug("Source peer %s did not provide chunk %s for healing", source_id, digest[:12], exc_info=True)
        return None

    pending_by_peer: dict[str, dict[str, Any]] = {}

    def queue_remote_chunk(peer: Peer, item: dict[str, Any]) -> None:
        bucket = pending_by_peer.setdefault(peer.node_id, {"peer": peer, "chunks": [], "bytes": 0})
        bucket["chunks"].append(item)
        bucket["bytes"] += int(item.get("stored_size", len(bytes(item["stored_data"]))))

    def flush_peer_bucket(node_id: str, *, reason: str = "batch") -> None:
        bucket = pending_by_peer.get(node_id)
        if not bucket or not bucket.get("chunks"):
            return
        peer: Peer = bucket["peer"]
        chunks: list[dict[str, Any]] = list(bucket["chunks"])
        pending_by_peer[node_id] = {"peer": peer, "chunks": [], "bytes": 0}
        name = peer_label(peer)
        first_index = min(int(item["entry_index"]) for item in chunks) if chunks else 0
        notify(
            phase="background_replication_batch",
            status=f"Sicherheitskopie wird im Hintergrund an {name} übertragen… +{len(chunks)} Chunks",
            current_chunk=min(first_index + len(chunks), max(total_chunks, 1)),
            total_chunks=total_chunks,
            current_peer=name,
            remote_successes=result.remote_successes,
            remote_failures=result.remote_failures,
            local_chunks=result.local_chunks,
            compressed_chunks=result.compressed_chunks,
            raw_bytes_processed=result.raw_bytes,
            stored_bytes=result.stored_bytes,
        )

        remaining = list(chunks)
        results = p2p_client.put_chunks_pack(peer, chunks=remaining)
        if len(results) != len(remaining) or any(not transfer.ok for transfer in results):
            json_results = p2p_client.put_chunks_batch(peer, chunks=remaining)
            if len(json_results) == len(remaining):
                results = [json_results[i] if not results or i >= len(results) or not results[i].ok else results[i] for i in range(len(remaining))]

        for item, transfer in zip(remaining, results):
            entry = result.chunks[int(item["entry_index"])]
            locations = [str(node_id) for node_id in entry.get("locations", []) if str(node_id)]
            if transfer.ok:
                if peer.node_id not in locations:
                    locations.append(peer.node_id)
                    entry["locations"] = list(dict.fromkeys(locations))
                result.remote_successes += 1
                continue

            result.remote_failures += 1
            stored = False
            alternate_peers = [
                candidate
                for candidate, _target_id in _rotated_targets(
                    ranked_peers,
                    [candidate.node_id for candidate in ranked_peers],
                    int(item["index"]) + 1,
                )
                if candidate is not None
            ]
            fallback_candidates: list[Peer] = []
            seen_fallbacks: set[str] = set()
            for candidate in [*alternate_peers, peer]:
                if candidate.node_id in seen_fallbacks or candidate.node_id in locations:
                    continue
                seen_fallbacks.add(candidate.node_id)
                fallback_candidates.append(candidate)
            for fallback_peer in fallback_candidates:
                fallback_name = peer_label(fallback_peer)
                notify(
                    phase="background_replication_retry",
                    status=f"Ein Chunk der Sicherheitskopie wird kleiner an {fallback_name} wiederholt…",
                    current_chunk=int(item["index"]) + 1,
                    total_chunks=total_chunks,
                    current_peer=fallback_name,
                )
                retry = p2p_client.put_chunk(
                    fallback_peer,
                    digest=str(item["digest"]),
                    stored_data=bytes(item["stored_data"]),
                    original_size=int(item["original_size"]),
                    stored_size=int(item["stored_size"]),
                    index=int(item["index"]),
                    compression=str(item["compression"]) if item.get("compression") else None,
                )
                if retry.ok:
                    retry_locations = [str(node_id) for node_id in entry.get("locations", []) if str(node_id)]
                    if fallback_peer.node_id not in retry_locations:
                        retry_locations.append(fallback_peer.node_id)
                        entry["locations"] = list(dict.fromkeys(retry_locations))
                    result.remote_successes += 1
                    stored = True
                    break
                result.remote_failures += 1
            if not stored:
                LOG.debug("Chunk %s could not be background-replicated: %s", str(item.get("digest", ""))[:12], transfer.message)

        notify(
            phase="background_replication_batch_done",
            status=f"Sicherheitskopie-Paket an {name} abgeschlossen ({reason})",
            current_chunk=min(first_index + len(chunks), max(total_chunks, 1)),
            total_chunks=total_chunks,
            current_peer=name,
            remote_successes=result.remote_successes,
            remote_failures=result.remote_failures,
            local_chunks=result.local_chunks,
            compressed_chunks=result.compressed_chunks,
            raw_bytes_processed=result.raw_bytes,
            stored_bytes=result.stored_bytes,
        )

    def flush_bucket_if_needed(peer: Peer) -> None:
        bucket = pending_by_peer.get(peer.node_id)
        if not bucket:
            return
        max_chunks, max_bytes = _upload_batch_limits(peer)
        if len(bucket["chunks"]) >= max_chunks or int(bucket["bytes"]) >= max_bytes:
            flush_peer_bucket(peer.node_id, reason="Limit erreicht")

    notify(
        phase="background_replication_start",
        status="Datei ist lokal gespeichert; Sicherheitskopien werden im Hintergrund verteilt…",
        current_chunk=0,
        total_chunks=total_chunks,
        target_count=len(result.targets),
        desired_replicas=desired_replicas,
        raw_bytes_processed=result.raw_bytes,
        stored_bytes=result.stored_bytes,
        local_chunks=result.local_chunks,
        compressed_chunks=result.compressed_chunks,
        remote_successes=0,
        remote_failures=0,
    )

    if not ranked_peers:
        for entry in result.chunks:
            if len(healthy_locations(entry)) < desired_replicas:
                result.under_replicated_chunks += 1
        notify(
            phase="background_replication_skipped",
            status="Keine aktiven Speicher-Peers verfügbar; RAID-1-Spiegel bleibt beim aktuellen Stand.",
            current_chunk=total_chunks,
            total_chunks=total_chunks,
            remote_successes=0,
            remote_failures=0,
            desired_replicas=desired_replicas,
        )
        return result

    ranked_ids = [peer.node_id for peer in ranked_peers]
    for entry_index, entry in enumerate(result.chunks):
        locations = [str(node_id) for node_id in entry.get("locations", []) if str(node_id)]
        healthy = healthy_locations(entry)
        missing_required_ids = required_ids.difference(healthy)
        if len(healthy) >= desired_replicas and not missing_required_ids:
            continue
        digest = str(entry.get("hash", ""))
        if not digest:
            continue
        stored_data = read_or_fetch_stored_data(entry)
        if stored_data is None:
            result.remote_failures += 1
            LOG.debug("Chunk %s has no currently readable source for RAID healing", digest[:12])
            continue
        candidates = [
            candidate
            for candidate, _target_id in _rotated_targets(ranked_peers, ranked_ids, int(entry.get("index", entry_index)))
            if candidate is not None and candidate.node_id not in healthy
        ]
        if missing_required_ids:
            required_candidates = [candidate for candidate in ranked_peers if candidate.node_id in missing_required_ids and candidate.node_id not in healthy]
            candidates = [*required_candidates, *[candidate for candidate in candidates if candidate.node_id not in missing_required_ids]]
        if not candidates:
            continue
        missing_copies = max(0, desired_replicas - len(healthy))
        if missing_required_ids:
            missing_copies = max(missing_copies, len(missing_required_ids))
        queued = 0
        for peer in candidates:
            queue_remote_chunk(
                peer,
                {
                    "entry_index": entry_index,
                    "digest": digest,
                    "stored_data": stored_data,
                    "original_size": int(entry.get("size", len(stored_data))),
                    "stored_size": int(entry.get("stored_size", len(stored_data))),
                    "index": int(entry.get("index", entry_index)),
                    "compression": entry.get("compression"),
                },
            )
            queued += 1
            flush_bucket_if_needed(peer)
            if queued >= missing_copies:
                break

    for node_id in list(pending_by_peer):
        flush_peer_bucket(node_id, reason="Hintergrundlauf abgeschlossen")

    result.replicated_chunks = 0
    result.under_replicated_chunks = 0
    for entry in result.chunks:
        locations = [str(node_id) for node_id in entry.get("locations", []) if str(node_id)]
        entry["locations"] = list(dict.fromkeys(locations)) or [local_node_id]
        healthy = healthy_locations(entry)
        if len(healthy) > 1:
            result.replicated_chunks += 1
        if len(healthy) < desired_replicas:
            result.under_replicated_chunks += 1

    notify(
        phase="background_replication_done",
        status="Hintergrund-Replikation abgeschlossen; Manifest wird aktualisiert…",
        current_chunk=total_chunks,
        total_chunks=total_chunks,
        raw_bytes_processed=result.raw_bytes,
        stored_bytes=result.stored_bytes,
        compressed_chunks=result.compressed_chunks,
        local_chunks=result.local_chunks,
        remote_successes=result.remote_successes,
        remote_failures=result.remote_failures,
    )
    return result
