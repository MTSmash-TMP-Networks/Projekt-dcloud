"""Peer provider abstractions and in-memory peer registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import ipaddress
import threading
from typing import Protocol


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
    external_ip: str | None = None
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def endpoint_key(self) -> tuple[str, int, str | None]:
        """Stable endpoint key used to prevent duplicate entries for the same address.

        Relay-only peers do not have a meaningful host/UDP endpoint. Include
        their node ID in the key so one PHP relay can hold many active nodes
        without collapsing them into a single duplicate endpoint.
        """
        if self.relay_url and self.host == "__relay__":
            return (f"relay:{self.relay_url}", 0, self.node_id)
        return (self.host, self.udp_port, self.route_via_node_id)

    def to_dict(self) -> dict[str, str | int | bool | float | None]:
        age = max(0.0, (datetime.now(timezone.utc) - self.last_seen).total_seconds())
        return {
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
            "external_ip": self.external_ip,
            "transport": "relay" if self.host == "__relay__" else ("direct+relay" if self.relay_url else "direct"),
            "display_name": display_name_for_peer(self.node_id, self.name),
            "last_seen": self.last_seen.isoformat(),
            "last_seen_age_seconds": round(age, 1),
            "status": "active",
        }


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


def _host_is_private_or_loopback(host: str) -> bool:
    value = (host or '').strip().lower()
    if value in {'localhost', '127.0.0.1', '::1'}:
        return True
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


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
                # field in this heartbeat, but always trust the latest route.
                peer.name = peer.name if peer.name is not None else existing.name
                peer.client_type = peer.client_type if peer.client_type is not None else existing.client_type
                peer.shared_storage_bytes = (
                    peer.shared_storage_bytes if peer.shared_storage_bytes is not None else existing.shared_storage_bytes
                )
                peer.accepts_peer_storage = (
                    peer.accepts_peer_storage if peer.accepts_peer_storage is not None else existing.accepts_peer_storage
                )
                peer.web_port = peer.web_port if peer.web_port is not None else existing.web_port
                peer.free_storage_bytes = (
                    peer.free_storage_bytes if peer.free_storage_bytes is not None else existing.free_storage_bytes
                )
                # Keep an already known LAN endpoint when the new heartbeat only
                # adds relay metadata, but do not pin an unreachable public IP.
                if peer.relay_url and not existing.relay_url:
                    if _host_is_private_or_loopback(existing.host) and not _host_is_private_or_loopback(peer.host):
                        peer.host = existing.host
                        peer.udp_port = existing.udp_port
                        peer.route_via_node_id = existing.route_via_node_id
                elif existing.relay_url and not peer.relay_url:
                    peer.relay_url = existing.relay_url

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
            peers = list(self._peers.values())
        return sorted(peers, key=lambda item: item.last_seen, reverse=True)

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
