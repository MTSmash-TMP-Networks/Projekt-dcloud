"""HTTP-based peer storage transfer helpers.

Discovery still happens over UDP port 6881. Once peers know each other, chunk
payloads are moved over the local Flask HTTP API because real chunks can be much
larger than one safe UDP datagram.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
import time
from typing import Any, Callable, Mapping
from urllib import error, parse, request

from .http_relay import RelayError, RelayHttpResponse, HttpRelayClient, RELAY_HOST
from .peers import Peer
from ..crypto import b64decode, derive_node_id, sign_bytes, verify_signature
from ..identity import NodeIdentity
from ..manifests import FileManifest, canonical_manifest_bytes
from ..storage import ChunkStore, StorageError

LOG = logging.getLogger(__name__)
REVOCATION_ACTION = "revoke_share"
FILE_DELETE_ACTION = "delete_file"
DEFAULT_MIN_REPLICAS_WITH_PEERS = 2


@dataclass(slots=True)
class PeerTransferResult:
    node_id: str
    ok: bool
    message: str = ""


@dataclass(slots=True)
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
    ) -> None:
        self.timeout = float(timeout)
        self.default_web_port = int(default_web_port)
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

    def _forward_via_relay(
        self,
        peer: Peer,
        *,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> RelayHttpResponse:
        relay_client = self._relay_client_for(peer)
        if relay_client is None:
            raise RelayError("Relay-Client ist nicht konfiguriert")
        return relay_client.forward_request(
            peer,
            method=method,
            path=path,
            headers=headers or {},
            body=body,
            timeout=relay_client.request_timeout,
        )

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
        url = f"{self.api_base(peer)}{path}"
        headers = {
            "Content-Type": "application/octet-stream",
            "X-DCloud-Chunk-Original-Size": str(int(original_size)),
            "X-DCloud-Chunk-Stored-Size": str(int(stored_size)),
            "X-DCloud-Chunk-Index": str(int(index)),
        }
        if compression:
            headers["X-DCloud-Chunk-Compression"] = compression
        if peer.host != RELAY_HOST:
            req = request.Request(url, data=stored_data, headers=headers, method="POST")
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
                    response = self._forward_via_relay(peer, method="POST", path=path, headers=headers, body=stored_data)
                    if 200 <= response.status_code < 300:
                        suffix = "" if attempt == 0 else f" nach Retry {attempt}"
                        return PeerTransferResult(peer.node_id, True, "stored via relay" + suffix)
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

    def get_chunk(self, peer: Peer, *, digest: str) -> bytes:
        path = f"/api/p2p/chunks/{parse.quote(digest)}"
        url = f"{self.api_base(peer)}{path}"
        direct_error: Exception | None = None
        if peer.host != RELAY_HOST:
            req = request.Request(url, headers={"Accept": "application/octet-stream"}, method="GET")
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
                    response = self._forward_via_relay(peer, method="GET", path=path, headers={"Accept": "application/octet-stream"})
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
        if peer.host != RELAY_HOST:
            url = f"{self.api_base(peer)}{path}"
            req = request.Request(url, data=data, headers=headers, method="POST")
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

    def post_manifest(self, peer: Peer, manifest: FileManifest) -> PeerTransferResult:
        return self._post_json_to_peer(
            peer,
            path="/api/p2p/manifests",
            payload=manifest.to_dict(),
            success_message="manifest shared",
            log_message="Manifest share to peer %s failed",
        )

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
    """Read a file once, compress each chunk and place it on local/peer targets.

    With active storage peers every chunk is written to at least two different
    nodes whenever possible. That keeps the file available when one node goes
    offline, while the primary slots still rotate through the network so storage
    is used evenly. If a remote write fails, the client tries the next target and
    finally falls back to the local node instead of losing data.
    """
    effective_chunk_size = int(chunk_size_bytes or chunk_store.chunk_size)
    if effective_chunk_size <= 0:
        effective_chunk_size = chunk_store.chunk_size

    if peers:
        # Prefer active remote storage first so even small one-chunk uploads use
        # decentralized capacity. The local node remains in the target ring to
        # provide a second copy when there is only one peer.
        targets: list[Peer | None] = [*peers, None]
        target_ids = [*[peer.node_id for peer in peers], local_node_id]
        desired_replicas = min(max(1, int(min_replicas_with_peers)), len(targets))
    else:
        targets = [None]
        target_ids = [local_node_id]
        desired_replicas = 1
    result = DistributedUploadResult(targets=list(dict.fromkeys(target_ids)), desired_replicas=desired_replicas)
    source_size = int(source_path.stat().st_size)
    total_chunks = (source_size + effective_chunk_size - 1) // effective_chunk_size if source_size else 0

    def notify(**payload: Any) -> None:
        if progress_callback is not None:
            progress_callback(payload)

    notify(
        phase="chunking_start",
        status="Datei wird in Chunks zerlegt und komprimiert…",
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
        while True:
            raw = handle.read(effective_chunk_size)
            if not raw:
                break
            notify(
                phase="chunk_read",
                status=f"Chunk {index + 1}/{max(total_chunks, 1)} wird gelesen…",
                current_chunk=index + 1,
                total_chunks=total_chunks,
                raw_bytes_processed=result.raw_bytes,
            )
            stored_data, compression = chunk_store.prepare_chunk_data(raw)
            digest = chunk_store.digest_for_stored_data(stored_data)
            locations: list[str] = []
            notify(
                phase="chunk_compressed",
                status=f"Chunk {index + 1}/{max(total_chunks, 1)} komprimiert: {len(raw)} -> {len(stored_data)} Bytes",
                current_chunk=index + 1,
                total_chunks=total_chunks,
                raw_bytes_processed=result.raw_bytes + len(raw),
                stored_bytes=result.stored_bytes + len(stored_data),
                compressed_chunks=result.compressed_chunks + (1 if compression else 0),
            )

            for target, node_id in _rotated_targets(targets, target_ids, index):
                if len(locations) >= desired_replicas:
                    break
                if node_id in locations:
                    continue
                if target is None:
                    notify(
                        phase="local_store",
                        status=f"Chunk {index + 1}/{max(total_chunks, 1)} wird lokal als Sicherheitskopie gespeichert…",
                        current_chunk=index + 1,
                        current_peer=local_node_id,
                    )
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
                    notify(
                        phase="local_store_done",
                        status=f"Chunk {index + 1}/{max(total_chunks, 1)} lokal gespeichert",
                        local_chunks=result.local_chunks,
                        current_peer=local_node_id,
                    )
                    continue

                peer_name = target.to_dict().get("display_name") or target.name or target.node_id[:12]
                notify(
                    phase="peer_upload",
                    status=f"Chunk {index + 1}/{max(total_chunks, 1)} wird an {peer_name} übertragen…",
                    current_chunk=index + 1,
                    current_peer=peer_name,
                )
                transfer = p2p_client.put_chunk(
                    target,
                    digest=digest,
                    stored_data=stored_data,
                    original_size=len(raw),
                    stored_size=len(stored_data),
                    index=index,
                    compression=compression,
                )
                if transfer.ok:
                    result.remote_successes += 1
                    locations.append(node_id)
                    notify(
                        phase="peer_upload_done",
                        status=f"Chunk {index + 1}/{max(total_chunks, 1)} auf {peer_name} gespeichert",
                        remote_successes=result.remote_successes,
                        current_peer=peer_name,
                    )
                else:
                    result.remote_failures += 1
                    notify(
                        phase="peer_upload_failed",
                        status=f"{peer_name} nicht erreichbar: {transfer.message or 'unbekannter Fehler'}; nächstes Ziel wird versucht…",
                        remote_failures=result.remote_failures,
                        current_peer=peer_name,
                        remote_error=transfer.message,
                    )

            if len(locations) < desired_replicas and local_node_id not in locations:
                # Last-resort safety copy. This path is important if every
                # remote peer failed before the local target was reached.
                notify(
                    phase="local_fallback",
                    status=f"Chunk {index + 1}/{max(total_chunks, 1)} bekommt eine lokale Fallback-Kopie…",
                    current_chunk=index + 1,
                    current_peer=local_node_id,
                )
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

            if len(locations) > 1:
                result.replicated_chunks += 1
            if len(locations) < desired_replicas:
                result.under_replicated_chunks += 1

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
            notify(
                phase="chunk_done",
                status=f"Chunk {index + 1}/{max(total_chunks, 1)} abgeschlossen",
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
