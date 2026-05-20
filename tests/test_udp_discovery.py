from pathlib import Path
import socket
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

from dcloud_client.config import DEFAULT_PUBLIC_RELAY_URL, load_config
from dcloud_client.identity import IdentityManager
from dcloud_client.network.peers import InMemoryPeerProvider, Peer
from dcloud_client.network.udp_discovery import UdpDiscoveryTransport


MIN_SHARED_BYTES = 5 * 1024**3


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def wait_until(predicate, timeout: float = 4.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


class UdpDiscoveryTests(unittest.TestCase):
    def test_peer_provider_prunes_offline_peers_after_timeout(self) -> None:
        provider = InMemoryPeerProvider(peer_timeout_seconds=0.15)
        provider.add_or_update(Peer(node_id="peer-a", host="127.0.0.1", udp_port=6881))
        self.assertIsNotNone(provider.get_peer("peer-a"))

        time.sleep(0.28)

        self.assertIsNone(provider.get_peer("peer-a"))
        self.assertEqual(provider.list_peers(), [])


    def test_peer_provider_keeps_peer_visible_within_grace_window(self) -> None:
        provider = InMemoryPeerProvider(peer_timeout_seconds=0.2)
        provider.add_or_update(Peer(node_id="peer-a", host="127.0.0.1", udp_port=6881))

        time.sleep(0.24)

        self.assertIsNotNone(provider.get_peer("peer-a"))

    def test_peer_provider_keeps_distinct_node_ids_on_same_endpoint(self) -> None:
        provider = InMemoryPeerProvider(peer_timeout_seconds=30)
        provider.add_or_update(Peer(node_id="old-node", host="127.0.0.1", udp_port=6881))
        provider.add_or_update(Peer(node_id="new-node", host="127.0.0.1", udp_port=6881))

        peers = provider.list_peers()
        self.assertEqual({peer.node_id for peer in peers}, {"old-node", "new-node"})
        self.assertIsNotNone(provider.get_peer("old-node"))

    def make_transport(
        self,
        root: Path,
        *,
        name: str,
        port: int,
        provider: InMemoryPeerProvider,
        auto_discovery_enabled: bool,
        auto_discovery_ports: list[int],
        peer_timeout_seconds: int = 30,
        peer_cleanup_interval_seconds: int = 1,
    ) -> tuple[UdpDiscoveryTransport, str]:
        identity = IdentityManager(root / f"{name}-identity").load_or_create()
        transport = UdpDiscoveryTransport(
            host="127.0.0.1",
            port=port,
            protocol_magic="DCLOUD1",
            identity=identity,
            node_name=name,
            peer_provider=provider,
            bootstrap_nodes=[],
            tree_parent_nodes=[],
            relay_children=False,
            discovery_interval_seconds=1,
            auto_discovery_enabled=auto_discovery_enabled,
            auto_discovery_ports=auto_discovery_ports,
            auto_discovery_hosts=["127.0.0.1"],
            startup_discovery_seconds=2,
            startup_discovery_interval_seconds=1,
            peer_timeout_seconds=peer_timeout_seconds,
            peer_cleanup_interval_seconds=peer_cleanup_interval_seconds,
            client_type="server" if name == "server" else "pc",
            shared_storage_bytes=MIN_SHARED_BYTES,
        )
        return transport, identity.node_id

    def test_auto_discovery_connects_to_visible_peer_port_without_manual_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            server_port = free_udp_port()
            pc_port = free_udp_port()
            server_provider = InMemoryPeerProvider()
            pc_provider = InMemoryPeerProvider()
            server, server_node_id = self.make_transport(
                root,
                name="server",
                port=server_port,
                provider=server_provider,
                auto_discovery_enabled=False,
                auto_discovery_ports=[server_port],
            )
            pc, pc_node_id = self.make_transport(
                root,
                name="pc",
                port=pc_port,
                provider=pc_provider,
                auto_discovery_enabled=True,
                auto_discovery_ports=[server_port],
            )

            try:
                server.start()
                time.sleep(0.05)
                pc.start()

                self.assertTrue(wait_until(lambda: pc_provider.get_peer(server_node_id) is not None))
                self.assertTrue(wait_until(lambda: server_provider.get_peer(pc_node_id) is not None))

                discovered_server = pc_provider.get_peer(server_node_id)
                self.assertIsNotNone(discovered_server)
                assert discovered_server is not None
                self.assertEqual(discovered_server.udp_port, server_port)
                self.assertEqual(discovered_server.client_type, "server")
            finally:
                pc.stop()
                server.stop()

    def test_offline_peer_is_removed_after_missed_discovery_rounds(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            server_port = free_udp_port()
            pc_port = free_udp_port()
            server_provider = InMemoryPeerProvider(peer_timeout_seconds=0.35)
            pc_provider = InMemoryPeerProvider(peer_timeout_seconds=0.35)
            server, server_node_id = self.make_transport(
                root,
                name="server",
                port=server_port,
                provider=server_provider,
                auto_discovery_enabled=False,
                auto_discovery_ports=[server_port],
            )
            pc, _ = self.make_transport(
                root,
                name="pc",
                port=pc_port,
                provider=pc_provider,
                auto_discovery_enabled=True,
                auto_discovery_ports=[server_port],
            )

            try:
                server.start()
                time.sleep(0.05)
                pc.start()
                self.assertTrue(wait_until(lambda: pc_provider.get_peer(server_node_id) is not None))

                server.stop()

                self.assertTrue(wait_until(lambda: pc_provider.get_peer(server_node_id) is None, timeout=2.0))
                self.assertEqual(pc_provider.list_peers(), [])
            finally:
                pc.stop()
                server.stop()

    def test_gossip_payload_does_not_mark_peer_active_before_it_answers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            provider = InMemoryPeerProvider()
            transport, _ = self.make_transport(
                root,
                name="pc",
                port=free_udp_port(),
                provider=provider,
                auto_discovery_enabled=False,
                auto_discovery_ports=[6881],
            )

            discovered = transport._ingest_peer_payload(
                [
                    {
                        "node_id": "candidate-node",
                        "host": "127.0.0.1",
                        "udp_port": free_udp_port(),
                        "name": "Gossip Candidate",
                        "client_type": "server",
                        "shared_storage_bytes": MIN_SHARED_BYTES,
                        "accepts_peer_storage": True,
                    }
                ],
                sender_node_id="sender-node",
            )

            self.assertEqual([peer.node_id for peer in discovered], ["candidate-node"])
            self.assertEqual(provider.list_peers(), [])

    def test_pc_transport_does_not_advertise_accepts_peer_storage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            provider = InMemoryPeerProvider()
            transport, _ = self.make_transport(
                root,
                name="pc",
                port=free_udp_port(),
                provider=provider,
                auto_discovery_enabled=False,
                auto_discovery_ports=[6881],
            )
            self.assertFalse(transport._accepts_peer_storage())


    def test_auto_discovery_broadcast_is_limited_to_local_slash24(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            provider = InMemoryPeerProvider()
            transport, _ = self.make_transport(
                root,
                name="pc",
                port=free_udp_port(),
                provider=provider,
                auto_discovery_enabled=True,
                auto_discovery_ports=[6881],
            )

            transport.host = "192.168.1.27"
            transport.auto_discovery_hosts = ["255.255.255.255"]
            targets = transport._auto_discovery_targets()

            self.assertIn(("192.168.1.255", 6881), {(node.host, node.port) for node in targets})
            self.assertNotIn(("255.255.255.255", 6881), {(node.host, node.port) for node in targets})

    def test_default_config_enables_lan_auto_discovery_on_port_6881(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = load_config(Path(temp_dir) / "config.yml")

        self.assertTrue(config.network.auto_discovery_enabled)
        self.assertEqual(config.network.auto_discovery_ports, [6881])
        self.assertIn("255.255.255.255", config.network.auto_discovery_hosts)
        self.assertLessEqual(config.network.startup_discovery_interval_seconds, 2)
        self.assertEqual(config.network.peer_timeout_seconds, 35)
        self.assertEqual(config.network.relay_url, DEFAULT_PUBLIC_RELAY_URL)
        self.assertIn(DEFAULT_PUBLIC_RELAY_URL, config.network.relay_urls)
        self.assertEqual(config.network.relay_poll_interval_seconds, 1)


if __name__ == "__main__":
    unittest.main()
