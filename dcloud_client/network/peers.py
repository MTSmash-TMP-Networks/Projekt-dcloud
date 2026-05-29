"""Peer provider abstractions and in-memory peer registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import ipaddress
import threading
from typing import Any, Protocol


DEFAULT_PEER_TIMEOUT_SECONDS = 35.0

_ADJECTIVES = [
    "Blauer", "Roter", "Goldener", "Silberner", "Grüner", "Mutiger",
    "Leiser", "Schneller", "Klarer", "Nordischer", "Sonniger", "Wilder",
]
_NOUNS = [
    "Falke", "Fuchs", "Biber", "Kompass", "Anker", "Komet",
    "Leuchtturm", "Ahorn", "Kranich", "Speicher", "Orbit", "Hafen",
]


def display_name_for_peer(node_id: str, configured_name: str | None = None) -> str:
    """Return a memorable, stable name for UI lists and sharing dialogs."""
    configured = (configured_name or "").strip()
    if configured and configured.lower() not in {"dcloud-node", "node", "client", "server"}:
        return configured
    digest = node_id.replace("-", "") or "0"
    try:
        number = int(digest[:8], 16)
    except ValueError:
        number = sum(ord(char) for char in digest)
    adjective = _ADJECTIVES[number % len(_ADJECTIVES)]
    noun = _NOUNS[(number // len(_ADJECTIVES)) % len(_NOUNS)]
    suffix = (digest[-4:] or "0000").upper()
    return f"{adjective} {noun} {suffix}"


def _address_is_lan_or_local(host: str | None) -> bool:
    """Return True when *host* is a local/LAN endpoint worth preferring.

    Direct/API discovery can report the same peer through an external route while
    UDP discovery sees it directly in the same LAN.  The direct LAN address is
    faster and more stable, so the peer registry keeps it as the primary route
    and stores relay metadata only as fallback.
    """
    value = (host or "").strip().strip("[]")
    if not value or value == "__relay__":
        return False
    if value.lower() in {"localhost", "host.docker.internal"}:
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value.endswith(".local") or ".local." in value
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
    )




def normalize_lan_addresses(values: object) -> list[str]:
    """Return clean direct-address candidates advertised by a peer.

    Peers discovered only through the PHP relay still announce their local
    interface addresses.  We keep those candidates separate from the active
    route so transfers can probe LAN HTTP first and use PHP only as fallback.
    """
    raw_items: list[object]
    if values is None:
        raw_items = []
    elif isinstance(values, (list, tuple, set)):
        raw_items = list(values)
    else:
        raw_items = [values]
    result: list[str] = []
    for item in raw_items:
        value = str(item or "").strip().strip("[]")
        if not value or value == "__relay__" or value in result:
            continue
        if _address_is_lan_or_local(value):
            result.append(value)
    return result



def normalize_chunk_inventory(value: object, *, max_manifests: int = 200, max_chunks_per_manifest: int = 512) -> dict[str, list[str]]:
    """Normalize tracker-advertised chunk availability.

    The PHP relay should act like a lightweight tracker: it may tell us which
    peer recently announced local copies for a manifest.  Keep the structure
    bounded because it is sent with regular heartbeats.
    """
    inventory: dict[str, list[str]] = {}

    def add(manifest_id: object, chunks: object) -> None:
        mid = str(manifest_id or "").strip()
        if not mid or len(inventory) >= max_manifests:
            return
        raw_chunks = chunks if isinstance(chunks, (list, tuple, set)) else []
        normalized: list[str] = []
        for item in raw_chunks:
            digest = str(item or "").strip()
            if not digest or digest in normalized:
                continue
            normalized.append(digest)
            if len(normalized) >= max_chunks_per_manifest:
                break
        if normalized:
            inventory[mid] = normalized

    if isinstance(value, dict):
        manifests = value.get("manifests")
        if isinstance(manifests, list):
            for item in manifests:
                if not isinstance(item, dict):
                    continue
                add(item.get("manifest_id"), item.get("chunk_hashes") or item.get("chunks") or [])
        else:
            for manifest_id, chunks in value.items():
                if str(manifest_id) in {"updated_at", "version"}:
                    continue
                add(manifest_id, chunks)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                add(item.get("manifest_id"), item.get("chunk_hashes") or item.get("chunks") or [])
    return inventory


def merge_chunk_inventory(*groups: object) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for group in groups:
        for manifest_id, chunks in normalize_chunk_inventory(group).items():
            bucket = merged.setdefault(manifest_id, [])
            for digest in chunks:
                if digest not in bucket:
                    bucket.append(digest)
    return merged

def merge_lan_addresses(*groups: object) -> list[str]:
    merged: list[str] = []
    for group in groups:
        for address in normalize_lan_addresses(group):
            if address not in merged:
                merged.append(address)
    return merged


def normalize_public_urls(values: object, *, max_urls: int = 16) -> list[str]:
    """Return clean http(s) public/NAT endpoint URLs.

    Unlike LAN candidates, these may be DDNS names or public IP routes and are
    often entered manually.  Keep only scheme, host and optional port/pathless
    base URL so transfers can probe the peer API directly without using PHP.
    """
    from urllib import parse

    raw_items: list[object]
    if values is None:
        raw_items = []
    elif isinstance(values, (list, tuple, set)):
        raw_items = list(values)
    else:
        raw_items = [values]
    result: list[str] = []
    for item in raw_items:
        value = str(item or "").strip().rstrip("/")
        if not value:
            continue
        if not value.lower().startswith(("http://", "https://")):
            value = "http://" + value
        try:
            parsed = parse.urlsplit(value)
        except Exception:
            continue
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").strip().strip("[]")
        if scheme not in {"http", "https"} or not host:
            continue
        try:
            port = parsed.port
        except ValueError:
            continue
        host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
        default_port = 443 if scheme == "https" else 80
        netloc = host_part if port in (None, default_port) else f"{host_part}:{port}"
        normalized = f"{scheme}://{netloc}"
        if normalized not in result:
            result.append(normalized)
        if len(result) >= max_urls:
            break
    return result


def merge_public_urls(*groups: object) -> list[str]:
    merged: list[str] = []
    for group in groups:
        for url in normalize_public_urls(group):
            if url not in merged:
                merged.append(url)
    return merged


def _route_preference(peer: "Peer") -> int:
    """Higher value means the peer route should be kept as primary."""
    if peer.host == "__relay__":
        return 0
    if peer.route_via_node_id:
        return 1
    if _address_is_lan_or_local(peer.host):
        return 3
    return 2


@dataclass
class Peer:
    node_id: str
    host: str
    udp_port: int
    name: str | None = None
    route_via_node_id: str | None = None
    client_type: str | None = None
    shared_storage_bytes: int | None = None
    accepts_peer_storage: bool | None = None
    web_port: int | None = None
    free_storage_bytes: int | None = None
    relay_url: str | None = None
    public_ip: str | None = None
    public_host: str | None = None
    public_port: int | None = None
    public_urls: list[str] = field(default_factory=list)
    scheme: str | None = None
    lan_addresses: list[str] = field(default_factory=list)
    chunk_inventory: dict[str, list[str]] = field(default_factory=dict)
    chat_enabled: bool = True
    chat_alias: str | None = None
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def endpoint_key(self) -> tuple[str, int, str | None]:
        """Stable endpoint key used to prevent duplicate entries for the same address.

        Route-only peers do not have a meaningful host/UDP endpoint. Include
        their node ID in the key so one PHP relay can hold many active nodes
        without collapsing them into a single duplicate endpoint.
        """
        if self.relay_url and self.host == "__relay__":
            return (f"relay:{self.relay_url}", 0, self.node_id)
        return (self.host, self.udp_port, self.route_via_node_id)

    def to_dict(self, *, include_chunk_inventory: bool = False) -> dict[str, Any]:
        age = max(0.0, (datetime.now(timezone.utc) - self.last_seen).total_seconds())
        inventory_manifest_count = len(self.chunk_inventory)
        inventory_chunk_count = sum(len(chunks) for chunks in self.chunk_inventory.values())
        payload: dict[str, Any] = {
            "node_id": self.node_id,
            "host": self.host,
            "udp_port": self.udp_port,
            "name": self.name,
            "route_via_node_id": self.route_via_node_id,
            "client_type": self.client_type,
            "shared_storage_bytes": self.shared_storage_bytes,
            "accepts_peer_storage": self.accepts_peer_storage,
            "web_port": self.web_port,
            "free_storage_bytes": self.free_storage_bytes,
            "relay_url": self.relay_url,
            "public_ip": self.public_ip,
            "public_host": self.public_host,
            "public_port": self.public_port,
            "public_urls": list(self.public_urls),
            "scheme": self.scheme or "http",
            "lan_addresses": list(self.lan_addresses),
            # The full digest inventory can be very large.  Keep dashboard/API and
            # LAN peer-list payloads small by default and expose only counters; the
            # in-memory Peer object still keeps the full tracker inventory for
            # download source selection.
            "tracker_manifest_count": inventory_manifest_count,
            "tracker_chunk_count": inventory_chunk_count,
            "chat_enabled": bool(self.chat_enabled),
            "chat_alias": self.chat_alias,
            "transport": "relay" if self.host == "__relay__" else ("direct+relay" if self.relay_url else "direct"),
            "display_name": display_name_for_peer(self.node_id, self.name),
            "last_seen": self.last_seen.isoformat(),
            "last_seen_age_seconds": round(age, 1),
            "status": "active",
        }
        if include_chunk_inventory:
            payload["chunk_inventory"] = {manifest_id: list(chunks) for manifest_id, chunks in self.chunk_inventory.items()}
        return payload


class PeerProvider(Protocol):
    def add_or_update(self, peer: Peer) -> None: ...
    def get_peer(self, node_id: str) -> Peer | None: ...
    def list_peers(self) -> list[Peer]: ...
    def remove(self, node_id: str) -> Peer | None: ...
    def purge_stale(self) -> list[Peer]: ...


class IndexProvider(Protocol):
    """Future extension point for DHT, federated index or local-only indices."""

    def announce_manifest(self, manifest_id: str, chunk_hashes: list[str]) -> None: ...
    def find_manifest(self, manifest_id: str) -> list[Peer]: ...
    def find_chunk(self, chunk_hash: str) -> list[Peer]: ...


class InMemoryPeerProvider:
    """Thread-safe registry that only exposes recently responsive peers.

    A peer becomes active only after we have received a direct discovery/control
    packet from its node ID. Gossiped peers should be probed first and only added
    after they answer. Entries that do not answer again within the configured
    timeout are removed automatically, and a changed identity at the same
    host/port replaces the older entry instead of creating duplicates.
    """

    def __init__(
        self,
        *,
        peer_timeout_seconds: float | None = None,
        stale_after_seconds: float | None = None,
    ) -> None:
        timeout = peer_timeout_seconds if peer_timeout_seconds is not None else stale_after_seconds
        if timeout is None:
            timeout = DEFAULT_PEER_TIMEOUT_SECONDS
        self.peer_timeout_seconds = max(0.05, float(timeout))
        # Backwards-compatible name for code/tests that used the previous term.
        self.stale_after_seconds = self.peer_timeout_seconds
        self._peers: dict[str, Peer] = {}
        self._lock = threading.Lock()

    def add_or_update(self, peer: Peer) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._purge_stale_locked(now)
            existing = self._peers.get(peer.node_id)
            if existing is not None:
                # Preserve useful metadata if an older peer did not advertise a
                # field in this heartbeat.  Route selection is intentionally not
                # "last write wins": LAN/direct discovery must stay primary when
                # the same peer is also visible through direct/API/public routes.
                peer.name = peer.name if peer.name is not None else existing.name
                peer.client_type = peer.client_type if peer.client_type is not None else existing.client_type
                peer.shared_storage_bytes = (
                    peer.shared_storage_bytes if peer.shared_storage_bytes is not None else existing.shared_storage_bytes
                )
                peer.accepts_peer_storage = (
                    peer.accepts_peer_storage if peer.accepts_peer_storage is not None else existing.accepts_peer_storage
                )
                peer.web_port = peer.web_port if peer.web_port is not None else existing.web_port
                peer.public_ip = peer.public_ip if peer.public_ip is not None else existing.public_ip
                peer.public_host = peer.public_host if peer.public_host is not None else existing.public_host
                peer.public_port = peer.public_port if peer.public_port is not None else existing.public_port
                peer.public_urls = merge_public_urls(peer.public_urls, existing.public_urls)
                peer.scheme = peer.scheme if peer.scheme is not None else existing.scheme
                peer.lan_addresses = merge_lan_addresses(peer.lan_addresses, existing.lan_addresses, [peer.host, existing.host])
                peer.chunk_inventory = merge_chunk_inventory(peer.chunk_inventory, existing.chunk_inventory)
                peer.free_storage_bytes = (
                    peer.free_storage_bytes if peer.free_storage_bytes is not None else existing.free_storage_bytes
                )
                if peer.chat_alias is None:
                    peer.chat_alias = existing.chat_alias

                existing_relay_url = existing.relay_url
                incoming_relay_url = peer.relay_url
                existing_priority = _route_preference(existing)
                incoming_priority = _route_preference(peer)

                if existing_priority > incoming_priority:
                    # Example: existing 192.168.x.x route, incoming __relay__ or
                    # public/API route.  Keep the LAN endpoint and merge only the
                    # fresh metadata/relay fallback.
                    peer.host = existing.host
                    peer.udp_port = existing.udp_port
                    peer.route_via_node_id = existing.route_via_node_id
                elif existing_priority == incoming_priority and _address_is_lan_or_local(existing.host) and not _address_is_lan_or_local(peer.host):
                    # Same class, but avoid replacing a LAN host with a public
                    # address when both announcements describe the same node.
                    peer.host = existing.host
                    peer.udp_port = existing.udp_port
                    peer.route_via_node_id = existing.route_via_node_id

                # Always keep a relay URL as fallback, regardless of which route
                # won above.  The active host stays LAN/direct when available.
                peer.relay_url = incoming_relay_url or existing_relay_url

            peer.lan_addresses = merge_lan_addresses(peer.lan_addresses, [peer.host])
            peer.chunk_inventory = normalize_chunk_inventory(peer.chunk_inventory)
            endpoint_key = peer.endpoint_key()
            duplicate_ids = [
                node_id
                for node_id, existing_peer in self._peers.items()
                if node_id != peer.node_id and existing_peer.endpoint_key() == endpoint_key
            ]
            for duplicate_id in duplicate_ids:
                self._peers.pop(duplicate_id, None)

            peer.last_seen = now
            self._peers[peer.node_id] = peer

    def get_peer(self, node_id: str) -> Peer | None:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._purge_stale_locked(now)
            return self._peers.get(node_id)

    def list_peers(self) -> list[Peer]:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._purge_stale_locked(now)
            # Keep insertion order stable for the dashboard.  Previously the list
            # was sorted by ``last_seen`` which made peers jump to the top every
            # time they announced themselves via UDP/API.  Python dicts
            # preserve insertion order, and assigning an existing node_id does
            # not move it, so existing rows keep their visible position while
            # newly discovered peers are appended at the end.
            return list(self._peers.values())

    def remove(self, node_id: str) -> Peer | None:
        with self._lock:
            return self._peers.pop(node_id, None)

    def purge_stale(self) -> list[Peer]:
        now = datetime.now(timezone.utc)
        with self._lock:
            return self._purge_stale_locked(now)

    def _purge_stale_locked(self, now: datetime) -> list[Peer]:
        cutoff = now - timedelta(seconds=self.peer_timeout_seconds)
        stale_ids = [node_id for node_id, peer in self._peers.items() if peer.last_seen < cutoff]
        return [self._peers.pop(node_id) for node_id in stale_ids]
