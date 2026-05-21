"""Minimal UDP discovery/control transport."""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from .http_relay import normalize_relay_urls
from .peers import Peer, PeerProvider
from ..identity import NodeIdentity

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class BootstrapNode:
    host: str
    port: int

    @classmethod
    def parse(cls, value: str) -> "BootstrapNode":
        host, _, port = value.rpartition(":")
        if not host or not port:
            raise ValueError(f"Invalid bootstrap node '{value}', expected host:port")
        return cls(host=host, port=int(port))


class UdpDiscoveryTransport:
    """Peer-to-peer UDP discovery with peer-list gossip and NAT tree relay.

    Every running client is also a small UDP server. A configured or manually
    added peer is only used as an entry point; after the first hello, nodes
    exchange their known peer lists so the mesh converges without a permanent
    central server. Nodes behind the same NAT can additionally register below
    one port-forwarded parent node. Other peers then address those children via
    the parent, which relays discovery/control messages through the tree.
    """

    def __init__(
        self,
        host: str,
        port: int,
        protocol_magic: str,
        identity: NodeIdentity,
        node_name: str,
        peer_provider: PeerProvider,
        bootstrap_nodes: list[str],
        tree_parent_nodes: list[str] | None = None,
        relay_children: bool = False,
        discovery_interval_seconds: int = 10,
        auto_discovery_enabled: bool = True,
        auto_discovery_ports: list[int] | None = None,
        auto_discovery_hosts: list[str] | None = None,
        startup_discovery_seconds: int = 12,
        startup_discovery_interval_seconds: int = 2,
        peer_timeout_seconds: float = 35,
        peer_cleanup_interval_seconds: float = 5,
        client_type: str = "server",
        shared_storage_bytes: int = 0,
        free_storage_bytes: int = 0,
        web_port: int | None = None,
        relay_urls: list[str] | None = None,
        relay_discovery_callback: Callable[[list[str]], None] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.protocol_magic = protocol_magic
        self.identity = identity
        self.node_name = node_name
        self.peer_provider = peer_provider
        self.bootstrap_nodes = [BootstrapNode.parse(node) for node in bootstrap_nodes]
        self.tree_parent_nodes = [BootstrapNode.parse(node) for node in tree_parent_nodes or []]
        self.relay_children = relay_children
        self.discovery_interval_seconds = max(1, int(discovery_interval_seconds))
        self.auto_discovery_enabled = bool(auto_discovery_enabled)
        self.auto_discovery_ports = self._normalize_ports(auto_discovery_ports or [6881])
        self.auto_discovery_hosts = self._normalize_hosts(auto_discovery_hosts or ["255.255.255.255"])
        self.startup_discovery_seconds = max(0, int(startup_discovery_seconds))
        self.startup_discovery_interval_seconds = max(1, int(startup_discovery_interval_seconds))
        self.peer_timeout_seconds = max(0.001, float(peer_timeout_seconds))
        self.peer_cleanup_interval_seconds = max(0.05, float(peer_cleanup_interval_seconds))
        self.client_type = client_type
        self.shared_storage_bytes = shared_storage_bytes
        self.free_storage_bytes = free_storage_bytes
        self.web_port = web_port
        self.relay_urls = normalize_relay_urls(relay_urls or [])
        self.relay_discovery_callback = relay_discovery_callback
        self.accepts_peer_storage = False
        self._child_node_ids: set[str] = set()
        self._socket: socket.socket | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._announce_thread: threading.Thread | None = None
        self._cleanup_thread: threading.Thread | None = None

    @staticmethod
    def _normalize_ports(raw_ports: list[int] | list[str]) -> list[int]:
        ports: list[int] = []
        for raw in raw_ports:
            port = int(raw)
            if not 1 <= port <= 65535:
                raise ValueError("Discovery port must be between 1 and 65535")
            if port not in ports:
                ports.append(port)
        return ports or [6881]

    @staticmethod
    def _normalize_hosts(raw_hosts: list[str]) -> list[str]:
        hosts: list[str] = []
        for raw in raw_hosts:
            host = str(raw).strip()
            if host and host not in hosts:
                hosts.append(host)
        return hosts or ["255.255.255.255"]

    def start(self) -> None:
        if self._socket is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(1.0)
        self._socket = sock
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._serve, name="udp-discovery", daemon=True)
        self._thread.start()
        self._announce_thread = threading.Thread(target=self._announce_loop, name="udp-announce", daemon=True)
        self._announce_thread.start()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, name="udp-peer-cleanup", daemon=True)
        self._cleanup_thread.start()
        LOG.info("UDP discovery listening on %s:%s", self.host, self.port)

    def stop(self) -> None:
        self._stop_event.set()
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        for thread in (self._thread, self._announce_thread, self._cleanup_thread):
            if thread is not None and thread.is_alive():
                thread.join(timeout=1.5)
        self._thread = None
        self._announce_thread = None
        self._cleanup_thread = None

    def add_peer_address(self, host: str, port: int, *, use_as_tree_parent: bool = False) -> None:
        """Manually add an entry-point peer and immediately start exchange."""
        self.send_control(host, port, self._hello_message(wants_relay_parent=use_as_tree_parent))

    def send_control(self, host: str, port: int, message: dict[str, object]) -> None:
        payload = {"magic": self.protocol_magic, **message}
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        temp_sock: socket.socket | None = None
        sock = self._socket
        if sock is None:
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock = temp_sock
        try:
            sock.sendto(data, (host, port))
        finally:
            if temp_sock is not None:
                temp_sock.close()

    def send_control_to_peer(self, peer: Peer, message: dict[str, object]) -> None:
        """Send directly or via the peer's NAT-tree parent."""
        if peer.route_via_node_id:
            route = self.peer_provider.get_peer(peer.route_via_node_id)
            if route is None:
                LOG.debug("Cannot relay to %s; missing route via %s", peer.node_id, peer.route_via_node_id)
                self._remove_peer(peer.node_id)
                return
            relay = {
                "type": "relay",
                "node_id": self.identity.node_id,
                "public_key": self.identity.public_key_b64,
                "name": self.node_name,
                "udp_port": self.port,
                "web_port": self.web_port,
                "client_type": self.client_type,
                "shared_storage_bytes": self.shared_storage_bytes,
                "free_storage_bytes": self.free_storage_bytes,
                "accepts_peer_storage": self.accepts_peer_storage,
                "relay_urls": self.relay_urls,
                "target_node_id": peer.node_id,
                "payload": message,
                "timestamp": int(time.time()),
            }
            self._safe_send_control(route.host, route.udp_port, relay)
            return
        self._safe_send_control(peer.host, peer.udp_port, message)

    def announce_once(self) -> None:
        self._purge_stale_peers()
        for node in self.bootstrap_nodes:
            self._safe_send_control(node.host, node.port, self._hello_message())
        for node in self.tree_parent_nodes:
            self._safe_send_control(node.host, node.port, self._hello_message(wants_relay_parent=True))
        for node in self._auto_discovery_targets():
            self._safe_send_control(node.host, node.port, self._hello_message())
        for peer in self.peer_provider.list_peers():
            self.send_control_to_peer(peer, self._hello_message())

    def _announce_loop(self) -> None:
        started_at = time.monotonic()
        while not self._stop_event.is_set():
            try:
                self.announce_once()
            except Exception:
                LOG.debug("Peer announcement failed", exc_info=True)
            delay = self.discovery_interval_seconds
            if time.monotonic() - started_at < self.startup_discovery_seconds:
                delay = min(delay, self.startup_discovery_interval_seconds)
            self._stop_event.wait(delay)

    def _cleanup_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._purge_stale_peers()
            except Exception:
                LOG.debug("Peer cleanup failed", exc_info=True)
            self._stop_event.wait(self.peer_cleanup_interval_seconds)

    def _safe_send_control(self, host: str, port: int, message: dict[str, object]) -> None:
        try:
            self.send_control(host, port, message)
        except OSError:
            LOG.debug("Discovery send to %s:%s failed", host, port, exc_info=True)

    def prune_stale_peers(self) -> list[str]:
        return self._purge_stale_peers()

    def _purge_stale_peers(self) -> list[str]:
        purge = getattr(self.peer_provider, "purge_stale", None)
        if not callable(purge):
            return []
        removed = list(purge())
        if not removed:
            return []
        removed_ids = {peer.node_id for peer in removed}
        self._child_node_ids.difference_update(removed_ids)
        LOG.info("Removed %s offline peer(s): %s", len(removed_ids), ", ".join(sorted(removed_ids))[:180])
        return list(removed_ids)

    def _remove_peer(self, node_id: str) -> None:
        remove = getattr(self.peer_provider, "remove", None)
        if callable(remove):
            removed = remove(node_id)
            if removed is not None:
                self._child_node_ids.discard(node_id)

    def _auto_discovery_targets(self) -> list[BootstrapNode]:
        if not self.auto_discovery_enabled:
            return []
        targets: list[BootstrapNode] = []
        seen: set[tuple[str, int]] = set()
        for host in self.auto_discovery_hosts:
            for port in self.auto_discovery_ports:
                key = (host, port)
                if key in seen:
                    continue
                seen.add(key)
                targets.append(BootstrapNode(host=host, port=port))
        return targets

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stop_event.is_set():
            try:
                data, address = self._socket.recvfrom(64 * 1024)
            except (OSError, socket.timeout):
                continue
            try:
                self._handle_packet(data, address)
            except Exception:
                LOG.debug("Ignored invalid UDP discovery packet from %s", address, exc_info=True)

    def _handle_packet(self, data: bytes, address: tuple[str, int]) -> None:
        message = json.loads(data.decode("utf-8"))
        if message.get("magic") != self.protocol_magic:
            return
        message_type = message.get("type")
        if message_type == "relay":
            self._handle_relay(message, address)
            return
        if message_type not in {"hello", "hello_ack", "peer_list"}:
            return

        sender = self._peer_from_message(message, address)
        if sender is None:
            return
        self.peer_provider.add_or_update(sender)
        self._ingest_relay_urls(message.get("relay_urls"))
        self._ingest_relay_urls(message.get("relay_url"))
        if self.relay_children and bool(message.get("wants_relay_parent")):
            self._child_node_ids.add(sender.node_id)

        discovered_peers = self._ingest_peer_payload(message.get("peers", []), sender.node_id)
        if message_type == "hello":
            self.send_control_to_peer(
                sender,
                {**self._hello_message(accepted_relay_parent=sender.node_id in self._child_node_ids), "type": "hello_ack"},
            )

        for peer in discovered_peers:
            self.send_control_to_peer(peer, self._hello_message())

        if message_type in {"hello", "hello_ack"}:
            self._gossip_peers(exclude_node_ids={sender.node_id})

    def _handle_relay(self, message: dict[str, Any], address: tuple[str, int]) -> None:
        if not self.relay_children:
            return
        sender = self._peer_from_message(message, address)
        if sender is not None:
            self.peer_provider.add_or_update(sender)
        target_node_id = str(message.get("target_node_id", ""))
        payload = message.get("payload")
        if not target_node_id or not isinstance(payload, dict):
            return
        if target_node_id not in self._child_node_ids and (sender is None or sender.node_id not in self._child_node_ids):
            return
        target = self.peer_provider.get_peer(target_node_id)
        if target is None or target.route_via_node_id:
            return
        relayed_payload = {**payload, "relayed_by": self.identity.node_id}
        self.send_control(target.host, target.udp_port, relayed_payload)

    def _peer_from_message(self, message: dict[str, Any], address: tuple[str, int]) -> Peer | None:
        node_id = str(message.get("node_id", ""))
        if not node_id or node_id == self.identity.node_id:
            return None
        advertised_port = int(message.get("udp_port", address[1]))
        if not 1 <= advertised_port <= 65535:
            return None
        route_via = message.get("relayed_by")
        relay_urls = normalize_relay_urls(message.get("relay_url") or message.get("relay_urls") or [])
        return Peer(
            node_id=node_id,
            host=address[0],
            udp_port=advertised_port,
            name=message.get("name"),
            route_via_node_id=str(route_via) if route_via else None,
            client_type=str(message.get("client_type")) if message.get("client_type") in {"server"} else None,
            shared_storage_bytes=int(message["shared_storage_bytes"]) if str(message.get("shared_storage_bytes", "")).isdigit() else None,
            accepts_peer_storage=bool(message.get("accepts_peer_storage")) if "accepts_peer_storage" in message else None,
            web_port=int(message["web_port"]) if str(message.get("web_port", "")).isdigit() else None,
            free_storage_bytes=int(message["free_storage_bytes"]) if str(message.get("free_storage_bytes", "")).isdigit() else None,
            relay_url=relay_urls[0] if relay_urls else None,
        )

    def _ingest_peer_payload(self, raw_peers: object, sender_node_id: str) -> list[Peer]:
        """Return gossiped peers that should be probed before becoming active.

        Indirect peer-list gossip must not refresh ``last_seen``. Otherwise one
        offline node can stay visible forever because other peers keep repeating
        an old list. A gossiped peer is therefore treated as a candidate only; it
        enters the active provider after it answers one of our hello messages.
        """
        if not isinstance(raw_peers, list):
            return []
        self._ingest_relay_urls([url for raw in raw_peers if isinstance(raw, dict) for url in normalize_relay_urls(raw.get("relay_urls") or raw.get("relay_url"))])
        active_peers = self.peer_provider.list_peers()
        active_ids = {peer.node_id for peer in active_peers}
        active_addresses = {peer.endpoint_key() for peer in active_peers}
        queued: set[tuple[str, str, int, str | None]] = set()
        discovered: list[Peer] = []
        for raw_peer in raw_peers:
            peer = self._peer_from_payload(raw_peer, sender_node_id)
            if peer is None or peer.node_id in active_ids or peer.endpoint_key() in active_addresses:
                continue
            key = (peer.node_id, peer.host, peer.udp_port, peer.route_via_node_id)
            if key in queued:
                continue
            queued.add(key)
            discovered.append(peer)
        return discovered

    def _peer_from_payload(self, raw_peer: object, sender_node_id: str) -> Peer | None:
        if not isinstance(raw_peer, dict):
            return None
        try:
            node_id = str(raw_peer["node_id"])
            route_via = raw_peer.get("route_via_node_id")
            relay_urls = normalize_relay_urls(raw_peer.get("relay_url") or raw_peer.get("relay_urls") or [])
            peer = Peer(
                node_id=node_id,
                host=str(raw_peer["host"]),
                udp_port=int(raw_peer["udp_port"]),
                name=raw_peer.get("name"),
                route_via_node_id=str(route_via) if route_via else None,
                client_type=str(raw_peer.get("client_type")) if raw_peer.get("client_type") in {"server"} else None,
                shared_storage_bytes=int(raw_peer["shared_storage_bytes"]) if str(raw_peer.get("shared_storage_bytes", "")).isdigit() else None,
                accepts_peer_storage=bool(raw_peer.get("accepts_peer_storage")) if "accepts_peer_storage" in raw_peer else None,
                web_port=int(raw_peer["web_port"]) if str(raw_peer.get("web_port", "")).isdigit() else None,
                free_storage_bytes=int(raw_peer["free_storage_bytes"]) if str(raw_peer.get("free_storage_bytes", "")).isdigit() else None,
                relay_url=relay_urls[0] if relay_urls else None,
            )
        except (KeyError, TypeError, ValueError):
            return None
        if not peer.node_id or peer.node_id == self.identity.node_id or not 1 <= peer.udp_port <= 65535:
            return None
        if peer.route_via_node_id == self.identity.node_id:
            return None
        if peer.route_via_node_id is None and peer.node_id in self._child_node_ids and sender_node_id != peer.node_id:
            peer.route_via_node_id = self.identity.node_id
        return peer

    def _gossip_peers(self, exclude_node_ids: set[str] | None = None) -> None:
        excluded = exclude_node_ids or set()
        for peer in self.peer_provider.list_peers():
            if peer.node_id in excluded:
                continue
            self.send_control_to_peer(peer, {**self._hello_message(for_peer=peer), "type": "peer_list"})

    def _ingest_relay_urls(self, raw_urls: object) -> None:
        urls = normalize_relay_urls(raw_urls)
        if not urls:
            return
        new_urls = [url for url in urls if url not in self.relay_urls]
        if not new_urls:
            return
        self.relay_urls.extend(new_urls)
        if self.relay_discovery_callback is not None:
            self.relay_discovery_callback(new_urls)

    def _known_peers_payload(self, for_peer: Peer | None = None) -> list[dict[str, str | int | bool | None]]:
        self._purge_stale_peers()
        payload: list[dict[str, str | int | bool | None]] = []
        for peer in self.peer_provider.list_peers()[:100]:
            if for_peer is not None and peer.node_id == for_peer.node_id:
                continue
            item = peer.to_dict()
            if peer.node_id in self._child_node_ids and (for_peer is None or for_peer.node_id != peer.node_id):
                item["route_via_node_id"] = self.identity.node_id
            payload.append(item)
        return payload

    def _accepts_peer_storage(self) -> bool:
        if self.client_type == "server":
            return True
        return True

    def _hello_message(
        self,
        *,
        for_peer: Peer | None = None,
        wants_relay_parent: bool = False,
        accepted_relay_parent: bool = False,
    ) -> dict[str, object]:
        self.accepts_peer_storage = self._accepts_peer_storage()
        return {
            "type": "hello",
            "node_id": self.identity.node_id,
            "public_key": self.identity.public_key_b64,
            "name": self.node_name,
            "udp_port": self.port,
            "relay_children": self.relay_children,
            "wants_relay_parent": wants_relay_parent,
            "accepted_relay_parent": accepted_relay_parent,
            "client_type": self.client_type,
            "shared_storage_bytes": self.shared_storage_bytes,
            "free_storage_bytes": self.free_storage_bytes,
            "accepts_peer_storage": self.accepts_peer_storage,
            "web_port": self.web_port,
            "relay_urls": self.relay_urls,
            "peers": self._known_peers_payload(for_peer=for_peer),
            "timestamp": int(time.time()),
        }
