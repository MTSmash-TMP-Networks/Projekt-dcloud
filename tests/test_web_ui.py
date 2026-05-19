from io import BytesIO
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from dcloud_client.config import AppConfig, DEFAULT_PUBLIC_RELAY_URL, NetworkConfig, NodeConfig, SecurityConfig, StorageConfig, UdpPortRange, WebConfig
from dcloud_client.identity import IdentityManager
from dcloud_client.manifests import DEFAULT_FOLDER, ManifestStore
from dcloud_client.network.peers import InMemoryPeerProvider, Peer
from dcloud_client.storage import ChunkStore
from dcloud_client.web.app import build_folder_tree, create_app
from werkzeug.serving import make_server


class _ServerThread(threading.Thread):
    def __init__(self, app, host: str, port: int) -> None:
        super().__init__(daemon=True)
        self.server = make_server(host, port, app)

    def run(self) -> None:
        self.server.serve_forever()

    def stop(self) -> None:
        self.server.shutdown()


def _free_tcp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


class FakePeerConnector:
    def __init__(self) -> None:
        self.announce_calls = 0
        self.added_peers: list[tuple[str, int, bool]] = []

    def add_peer_address(self, host: str, port: int, *, use_as_tree_parent: bool = False) -> None:
        self.added_peers.append((host, port, use_as_tree_parent))

    def announce_once(self) -> None:
        self.announce_calls += 1


class WebUiTests(unittest.TestCase):
    def make_app(
        self,
        root: Path,
        *,
        peer_provider: InMemoryPeerProvider | None = None,
        peer_connector: FakePeerConnector | None = None,
        client_type: str = "pc",
    ):
        identity = IdentityManager(root / "identity").load_or_create()
        chunk_store = ChunkStore(root / "storage", limit_bytes=20 * 1024 * 1024, min_free_bytes=0, chunk_size=64)
        chunk_store.initialize()
        manifest_store = ManifestStore(chunk_store)
        config = AppConfig(
            node=NodeConfig(name="test-node", identity_path=root / "identity", client_type=client_type),
            storage=StorageConfig(path=root / "storage", limit_bytes=20 * 1024 * 1024, min_free_bytes=0, chunk_size_bytes=64),
            web=WebConfig(host="127.0.0.1", port=8787),
            network=NetworkConfig(
                udp_host="127.0.0.1",
                udp_port=6881,
                udp_port_range=UdpPortRange(start=6881, end=6891),
            ),
            security=SecurityConfig(protocol_magic="DCLOUD1"),
            config_path=root / "config.yml",
        )
        app = create_app(config, identity, chunk_store, manifest_store, peer_provider or InMemoryPeerProvider(), peer_connector)
        app.testing = True
        return app, identity, manifest_store

    def make_node_app(
        self,
        root: Path,
        *,
        name: str,
        web_port: int,
        client_type: str = "server",
        peer_provider: InMemoryPeerProvider | None = None,
    ):
        identity = IdentityManager(root / f"{name}-identity").load_or_create()
        chunk_store = ChunkStore(root / f"{name}-storage", limit_bytes=20 * 1024 * 1024, min_free_bytes=0, chunk_size=64)
        chunk_store.initialize()
        manifest_store = ManifestStore(chunk_store)
        config = AppConfig(
            node=NodeConfig(name=name, identity_path=root / f"{name}-identity", client_type=client_type),
            storage=StorageConfig(path=root / f"{name}-storage", limit_bytes=20 * 1024 * 1024, min_free_bytes=0, chunk_size_bytes=64),
            web=WebConfig(host="127.0.0.1", port=web_port),
            network=NetworkConfig(
                udp_host="127.0.0.1",
                udp_port=6881,
                udp_port_range=UdpPortRange(start=6881, end=6891),
            ),
            security=SecurityConfig(protocol_magic="DCLOUD1"),
            config_path=root / f"{name}-config.yml",
        )
        app = create_app(config, identity, chunk_store, manifest_store, peer_provider or InMemoryPeerProvider())
        app.testing = True
        return app, identity, chunk_store, manifest_store

    def test_folder_tree_uses_user_created_folders(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)
            document = root / "report.pdf"
            image = root / "diagram.png"
            document.write_bytes(b"document" * 20)
            image.write_bytes(b"image" * 20)

            manifest_store.create_folder("Projekte/Kunde A", identity.node_id)
            manifest_store.create_for_file(document, identity, folder_path="Projekte/Kunde A")
            manifest_store.create_for_file(image, identity)

            folders = build_folder_tree(
                manifest_store.list_visible_for_node(identity.node_id),
                manifest_store.list_folders_for_node(identity.node_id),
            )
            self.assertEqual([folder["name"] for folder in folders], [DEFAULT_FOLDER, "Projekte/Kunde A"])
            self.assertEqual([len(folder["files"]) for folder in folders], [1, 1])
            with app.test_client() as client:
                response = client.get("/")
            self.assertIn(b"dcloud Datenspeicher - Datei-Explorer", response.data)
            self.assertIn("Ordner erstellen".encode(), response.data)
            self.assertIn("Projekte/Kunde A".encode(), response.data)

    def test_delete_from_files_ui_removes_manifest_and_redirects_back_to_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)
            source = root / "delete-me.txt"
            source.write_bytes(b"delete me" * 20)
            manifest = manifest_store.create_for_file(source, identity)

            with app.test_client() as client:
                response = client.post(
                    f"/files/{manifest.manifest_id}/delete",
                    data={"next": "/files"},
                    follow_redirects=False,
                )

            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["Location"], "/files")
            self.assertFalse(manifest_store.path_for(manifest.manifest_id).exists())

    def test_private_peer_manifest_is_hidden_until_shared(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)
            peer_identity = IdentityManager(root / "peer-identity").load_or_create()
            source = root / "peer-secret.txt"
            source.write_bytes(b"secret" * 20)
            manifest = manifest_store.create_for_file(source, peer_identity)

            self.assertEqual(manifest_store.list_visible_for_node(identity.node_id), [])
            shared = manifest_store.set_shared(manifest.manifest_id, True, peer_identity)
            visible_names = [item.file_name for item in manifest_store.list_visible_for_node(identity.node_id)]
            self.assertEqual(visible_names, ["peer-secret.txt"])

            with app.test_client() as client:
                response = client.get("/files")
            self.assertIn(b"peer-secret.txt", response.data)
            self.assertIn("freigegeben".encode(), response.data)
            self.assertTrue(manifest_store.is_shared(shared))

    def test_create_folder_and_share_from_ui(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)
            source = root / "share-me.txt"
            source.write_bytes(b"share" * 20)
            manifest = manifest_store.create_for_file(source, identity)

            with app.test_client() as client:
                folder_response = client.post("/folders", data={"folder": "Team", "next": "/files"})
                share_response = client.post(
                    f"/files/{manifest.manifest_id}/share",
                    data={"shared": "on", "next": "/files"},
                )

            self.assertEqual(folder_response.status_code, 302)
            self.assertIn("Team", manifest_store.list_folders_for_node(identity.node_id))
            self.assertEqual(share_response.status_code, 302)
            shared_manifest = manifest_store.list_visible_for_node(identity.node_id)[0]
            self.assertEqual(shared_manifest.access["visibility"], "shared")

    def test_ajax_folder_and_upload_return_updated_desktop_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)

            with app.test_client() as client:
                folder_response = client.post(
                    "/folders",
                    data={"folder": "Desktop Projekte", "next": "/"},
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )
                upload_response = client.post(
                    "/upload",
                    data={
                        "folder": "Desktop Projekte",
                        "next": "/",
                        "file": (BytesIO(b"hello desktop" * 20), "desktop-note.txt"),
                    },
                    content_type="multipart/form-data",
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )

            self.assertEqual(folder_response.status_code, 200)
            self.assertTrue(folder_response.json["ok"])
            self.assertIn("Desktop Projekte", folder_response.json["state"]["folders"])
            self.assertEqual(upload_response.status_code, 200)
            self.assertTrue(upload_response.json["ok"])
            self.assertEqual(upload_response.json["manifest"]["file_name"], "desktop-note.txt")
            self.assertEqual(upload_response.json["state"]["fileCount"], 1)

    def test_dashboard_upload_window_exposes_detailed_progress_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)

            with app.test_client() as client:
                response = client.get("/")

            self.assertEqual(response.status_code, 200)
            self.assertIn(b"transfer-client-progress", response.data)
            self.assertIn(b"transfer-server-progress", response.data)
            self.assertIn(b"transfer-peer-progress", response.data)
            self.assertIn("Server-Verarbeitung".encode(), response.data)
            self.assertIn(b"/api/uploads/", response.data)

    def test_api_state_disables_caching(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)

            with app.test_client() as client:
                response = client.get("/api/state")

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers.get("Cache-Control"), "no-store")
            self.assertEqual(response.headers.get("Pragma"), "no-cache")
            self.assertEqual(response.headers.get("Expires"), "0")

    def test_ajax_upload_exposes_server_side_progress_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)
            upload_id = "status-test-upload"

            with app.test_client() as client:
                pending = client.get(f"/api/uploads/{upload_id}")
                response = client.post(
                    "/upload",
                    data={
                        "upload_id": upload_id,
                        "folder": DEFAULT_FOLDER,
                        "next": "/",
                        "file": (BytesIO(b"progress-data-" * 40), "progress.bin"),
                    },
                    content_type="multipart/form-data",
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )
                progress = client.get(f"/api/uploads/{upload_id}")

            self.assertEqual(pending.status_code, 200)
            self.assertFalse(pending.json["known"])
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json["ok"])
            self.assertIn("uploadProgress", response.json)
            self.assertEqual(response.json["uploadProgress"]["phase"], "complete")
            self.assertFalse(response.json["uploadProgress"]["active"])
            self.assertEqual(response.json["uploadProgress"]["percent"], 100)
            self.assertGreaterEqual(response.json["uploadProgress"]["totalChunks"], 2)
            self.assertGreater(response.json["uploadProgress"]["storedBytes"], 0)
            self.assertEqual(progress.status_code, 200)
            self.assertTrue(progress.json["known"])
            self.assertEqual(progress.json["ok"], True)
            self.assertEqual(progress.json["details"]["manifestId"], response.json["manifest"]["manifest_id"])

    def test_ajax_delete_folder_removes_owned_files_and_subfolders(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)
            keep = root / "keep.txt"
            top = root / "top.txt"
            nested = root / "nested.txt"
            keep.write_bytes(b"keep" * 20)
            top.write_bytes(b"top" * 20)
            nested.write_bytes(b"nested" * 20)

            manifest_store.create_folder("Projekte/Archiv", identity.node_id)
            manifest_store.create_for_file(keep, identity, folder_path="Andere")
            top_manifest = manifest_store.create_for_file(top, identity, folder_path="Projekte")
            nested_manifest = manifest_store.create_for_file(nested, identity, folder_path="Projekte/Archiv")

            with app.test_client() as client:
                response = client.post(
                    "/folders/delete",
                    data={"folder": "Projekte", "next": "/"},
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )

            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json["ok"])
            self.assertEqual(response.json["deleted"]["deleted_files"], 2)
            self.assertFalse(manifest_store.path_for(top_manifest.manifest_id).exists())
            self.assertFalse(manifest_store.path_for(nested_manifest.manifest_id).exists())
            self.assertEqual([item.file_name for item in manifest_store.list_visible_for_node(identity.node_id)], ["keep.txt"])
            self.assertNotIn("Projekte", manifest_store.list_folders_for_node(identity.node_id))
            self.assertNotIn("Projekte/Archiv", manifest_store.list_folders_for_node(identity.node_id))

    def test_default_folder_cannot_be_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)

            with app.test_client() as client:
                response = client.post(
                    "/folders/delete",
                    data={"folder": DEFAULT_FOLDER, "next": "/"},
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )

            self.assertEqual(response.status_code, 400)
            self.assertFalse(response.json["ok"])
            self.assertIn(DEFAULT_FOLDER, manifest_store.list_folders_for_node(identity.node_id))


    def test_ajax_settings_update_client_type_and_shared_storage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)

            with app.test_client() as client:
                response = client.post(
                    "/settings",
                    data={"client_type": "server", "shared_storage_gb": "8", "next": "/"},
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )

            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json["ok"])
            self.assertEqual(response.json["state"]["settings"]["clientType"], "server")
            self.assertEqual(response.json["state"]["settings"]["sharedStorageBytes"], 8 * 1024**3)
            live_config = app.config["DCLOUD_APP_CONFIG"]
            self.assertEqual(live_config.node.client_type, "server")
            self.assertEqual(live_config.storage.limit_bytes, 8 * 1024**3)

    def test_settings_rejects_shared_storage_below_minimum(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)

            with app.test_client() as client:
                response = client.post(
                    "/settings",
                    data={"client_type": "pc", "shared_storage_gb": "4", "next": "/"},
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )

            self.assertEqual(response.status_code, 400)
            self.assertFalse(response.json["ok"])
            self.assertIn("Mindestens 5 GB", response.json["message"])

    def test_ajax_discovery_refresh_triggers_immediate_announce(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            connector = FakePeerConnector()
            app, identity, manifest_store = self.make_app(root, peer_connector=connector)

            with app.test_client() as client:
                response = client.post(
                    "/api/discovery/announce",
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )

            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json["ok"])
            self.assertEqual(connector.announce_calls, 1)
            self.assertEqual(response.json["state"]["network"]["autoDiscoveryPorts"], [6881])


    def test_client_type_policy_is_exposed_in_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            peer_provider = InMemoryPeerProvider()
            peer_provider.add_or_update(Peer(
                node_id="peer-pc",
                host="127.0.0.2",
                udp_port=6882,
                name="Wohnzimmer-PC",
                client_type="pc",
                accepts_peer_storage=False,
            ))
            app, identity, manifest_store = self.make_app(root, peer_provider=peer_provider, client_type="pc")

            with app.test_client() as client:
                response = client.get("/api/state")

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["settings"]["clientType"], "pc")
            self.assertTrue(response.json["settings"]["acceptsPeerStorage"])
            self.assertIn("mindestens ein weiterer PC", response.json["settings"]["storagePolicy"])

    def test_server_peer_is_used_as_upload_storage_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            peer_provider = InMemoryPeerProvider()
            peer_provider.add_or_update(Peer(
                node_id="server-peer",
                host="127.0.0.3",
                udp_port=6883,
                name="Keller-Server",
                client_type="server",
                shared_storage_bytes=50 * 1024**3,
                accepts_peer_storage=True,
            ))
            app, identity, manifest_store = self.make_app(root, peer_provider=peer_provider, client_type="pc")

            with app.test_client() as client:
                response = client.post(
                    "/upload",
                    data={
                        "folder": DEFAULT_FOLDER,
                        "next": "/",
                        "file": (BytesIO(b"placement" * 20), "placement.txt"),
                    },
                    content_type="multipart/form-data",
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )

            self.assertEqual(response.status_code, 200)
            manifest_id = response.json["manifest"]["manifest_id"]
            manifest = manifest_store.load(manifest_id)
            self.assertEqual(manifest.placement["targets"], ["server-peer", identity.node_id])
            self.assertEqual(manifest.placement["transfer_status"], "local_fallback")

    def test_upload_from_files_ui_redirects_back_to_files_without_ajax(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)

            with app.test_client() as client:
                response = client.post(
                    "/upload",
                    data={
                        "folder": DEFAULT_FOLDER,
                        "next": "/files",
                        "file": (BytesIO(b"plain form" * 20), "form-upload.txt"),
                    },
                    content_type="multipart/form-data",
                    follow_redirects=False,
                )

            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["Location"], "/files")
            self.assertEqual([item.file_name for item in manifest_store.list_visible_for_node(identity.node_id)], ["form-upload.txt"])

    def test_upload_transfers_chunks_to_active_storage_peer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            peer_port = _free_tcp_port()
            peer_app, peer_identity, peer_chunk_store, peer_manifest_store = self.make_node_app(
                root, name="peer-server", web_port=peer_port, client_type="server"
            )
            peer_server = _ServerThread(peer_app, "127.0.0.1", peer_port)
            peer_server.start()
            try:
                owner_provider = InMemoryPeerProvider()
                owner_provider.add_or_update(Peer(
                    node_id=peer_identity.node_id,
                    host="127.0.0.1",
                    udp_port=6882,
                    name="Keller-Server",
                    client_type="server",
                    shared_storage_bytes=20 * 1024 * 1024,
                    free_storage_bytes=20 * 1024 * 1024,
                    accepts_peer_storage=True,
                    web_port=peer_port,
                ))
                owner_app, owner_identity, owner_chunk_store, owner_manifest_store = self.make_node_app(
                    root, name="owner", web_port=_free_tcp_port(), client_type="pc", peer_provider=owner_provider
                )

                with owner_app.test_client() as client:
                    response = client.post(
                        "/upload",
                        data={
                            "folder": DEFAULT_FOLDER,
                            "next": "/",
                            "file": (BytesIO(b"peer distributed data " * 30), "distributed.txt"),
                        },
                        content_type="multipart/form-data",
                        headers={"X-Requested-With": "XMLHttpRequest"},
                    )

                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.json["ok"])
                manifest = owner_manifest_store.load(response.json["manifest"]["manifest_id"])
                remote_chunks = [chunk for chunk in manifest.chunks if peer_identity.node_id in chunk.get("locations", [])]
                self.assertGreater(len(remote_chunks), 0)
                self.assertEqual(manifest.placement["transfer_status"], "stored_on_peers")
                self.assertTrue(all(peer_chunk_store.chunk_path(str(chunk["hash"])).exists() for chunk in remote_chunks))
                state = response.json["state"]
                self.assertGreater(state["settings"]["networkLimitBytes"], state["stats"]["limitBytes"])
            finally:
                peer_server.stop()

    def test_share_to_selected_peer_delivers_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            peer_port = _free_tcp_port()
            peer_app, peer_identity, peer_chunk_store, peer_manifest_store = self.make_node_app(
                root, name="share-target", web_port=peer_port, client_type="server"
            )
            peer_server = _ServerThread(peer_app, "127.0.0.1", peer_port)
            peer_server.start()
            try:
                owner_provider = InMemoryPeerProvider()
                owner_provider.add_or_update(Peer(
                    node_id=peer_identity.node_id,
                    host="127.0.0.1",
                    udp_port=6882,
                    name="Blauer Falke",
                    client_type="server",
                    shared_storage_bytes=20 * 1024 * 1024,
                    free_storage_bytes=20 * 1024 * 1024,
                    accepts_peer_storage=True,
                    web_port=peer_port,
                ))
                owner_app, owner_identity, owner_chunk_store, owner_manifest_store = self.make_node_app(
                    root, name="share-owner", web_port=_free_tcp_port(), client_type="pc", peer_provider=owner_provider
                )
                source = root / "share-me.txt"
                source.write_bytes(b"share me" * 20)
                manifest = owner_manifest_store.create_for_file(source, owner_identity)

                with owner_app.test_client() as client:
                    response = client.post(
                        f"/files/{manifest.manifest_id}/share",
                        data={"next": "/", "shared": "on", "peer_node_id": peer_identity.node_id},
                        headers={"X-Requested-With": "XMLHttpRequest"},
                    )

                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.json["ok"])
                shared_manifest_id = response.json["manifest"]["manifest_id"]
                shared_manifest = owner_manifest_store.load(shared_manifest_id)
                self.assertEqual(shared_manifest.access["shared_with"], [peer_identity.node_id])
                remote_visible = peer_manifest_store.list_visible_for_node(peer_identity.node_id)
                self.assertEqual([manifest.file_name for manifest in remote_visible], ["share-me.txt"])
            finally:
                peer_server.stop()


    def test_upload_with_single_peer_keeps_local_replica_for_offline_safety(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            peer_port = _free_tcp_port()
            peer_app, peer_identity, peer_chunk_store, peer_manifest_store = self.make_node_app(
                root, name="replica-peer", web_port=peer_port, client_type="server"
            )
            peer_server = _ServerThread(peer_app, "127.0.0.1", peer_port)
            peer_server.start()
            try:
                owner_provider = InMemoryPeerProvider()
                owner_provider.add_or_update(Peer(
                    node_id=peer_identity.node_id,
                    host="127.0.0.1",
                    udp_port=6882,
                    name="Replica Server",
                    client_type="server",
                    shared_storage_bytes=20 * 1024 * 1024,
                    free_storage_bytes=20 * 1024 * 1024,
                    accepts_peer_storage=True,
                    web_port=peer_port,
                ))
                owner_app, owner_identity, owner_chunk_store, owner_manifest_store = self.make_node_app(
                    root, name="replica-owner", web_port=_free_tcp_port(), client_type="pc", peer_provider=owner_provider
                )
                payload = b"redundant data block " * 30

                with owner_app.test_client() as client:
                    response = client.post(
                        "/upload",
                        data={
                            "folder": DEFAULT_FOLDER,
                            "next": "/",
                            "file": (BytesIO(payload), "redundant.txt"),
                        },
                        content_type="multipart/form-data",
                        headers={"X-Requested-With": "XMLHttpRequest"},
                    )

                self.assertEqual(response.status_code, 200)
                manifest = owner_manifest_store.load(response.json["manifest"]["manifest_id"])
                self.assertEqual(manifest.placement["desired_replicas"], 2)
                self.assertEqual(manifest.placement["replicated_chunks"], len(manifest.chunks))
                for chunk in manifest.chunks:
                    locations = set(chunk.get("locations", []))
                    self.assertIn(owner_identity.node_id, locations)
                    self.assertIn(peer_identity.node_id, locations)
                    self.assertTrue(owner_chunk_store.chunk_path(str(chunk["hash"])).exists())
                    self.assertTrue(peer_chunk_store.chunk_path(str(chunk["hash"])).exists())
            finally:
                peer_server.stop()

            # After the only remote peer goes offline, the owner can still
            # restore the file because every chunk has a local safety copy.
            with owner_app.test_client() as client:
                download_response = client.get(f"/download/{manifest.manifest_id}")
            self.assertEqual(download_response.status_code, 200)
            self.assertEqual(download_response.data, payload)

    def test_unshare_selected_peer_revokes_remote_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            peer_port = _free_tcp_port()
            peer_app, peer_identity, peer_chunk_store, peer_manifest_store = self.make_node_app(
                root, name="revoke-target", web_port=peer_port, client_type="server"
            )
            peer_server = _ServerThread(peer_app, "127.0.0.1", peer_port)
            peer_server.start()
            try:
                owner_provider = InMemoryPeerProvider()
                owner_provider.add_or_update(Peer(
                    node_id=peer_identity.node_id,
                    host="127.0.0.1",
                    udp_port=6882,
                    name="Revoke Target",
                    client_type="server",
                    shared_storage_bytes=20 * 1024 * 1024,
                    free_storage_bytes=20 * 1024 * 1024,
                    accepts_peer_storage=True,
                    web_port=peer_port,
                ))
                owner_app, owner_identity, owner_chunk_store, owner_manifest_store = self.make_node_app(
                    root, name="revoke-owner", web_port=_free_tcp_port(), client_type="pc", peer_provider=owner_provider
                )
                source = root / "temporary-share.txt"
                source.write_bytes(b"temporary share" * 20)
                manifest = owner_manifest_store.create_for_file(source, owner_identity)

                with owner_app.test_client() as client:
                    share_response = client.post(
                        f"/files/{manifest.manifest_id}/share",
                        data={"next": "/", "shared": "on", "peer_node_id": peer_identity.node_id},
                        headers={"X-Requested-With": "XMLHttpRequest"},
                    )
                    self.assertEqual(share_response.status_code, 200)
                    shared_manifest_id = share_response.json["manifest"]["manifest_id"]
                    shared_manifest_payload = owner_manifest_store.load(shared_manifest_id).to_dict()
                    self.assertEqual(
                        [item.file_name for item in peer_manifest_store.list_visible_for_node(peer_identity.node_id)],
                        ["temporary-share.txt"],
                    )

                    unshare_response = client.post(
                        f"/files/{shared_manifest_id}/share",
                        data={"next": "/", "shared": "off"},
                        headers={"X-Requested-With": "XMLHttpRequest"},
                    )

                self.assertEqual(unshare_response.status_code, 200)
                self.assertTrue(unshare_response.json["ok"])
                private_manifest = owner_manifest_store.load(unshare_response.json["manifest"]["manifest_id"])
                self.assertEqual(private_manifest.access["visibility"], "private")
                self.assertFalse(peer_manifest_store.path_for(shared_manifest_id).exists())
                self.assertEqual(peer_manifest_store.list_visible_for_node(peer_identity.node_id), [])

                with peer_app.test_client() as peer_client:
                    replay = peer_client.post("/api/p2p/manifests", json=shared_manifest_payload)
                self.assertEqual(replay.status_code, 400)
            finally:
                peer_server.stop()


    def test_owner_delete_removes_remote_manifest_and_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            peer_port = _free_tcp_port()
            peer_app, peer_identity, peer_chunk_store, peer_manifest_store = self.make_node_app(
                root, name="delete-sync-peer", web_port=peer_port, client_type="server"
            )
            peer_server = _ServerThread(peer_app, "127.0.0.1", peer_port)
            peer_server.start()
            try:
                owner_provider = InMemoryPeerProvider()
                owner_provider.add_or_update(Peer(
                    node_id=peer_identity.node_id,
                    host="127.0.0.1",
                    udp_port=6882,
                    name="Delete Sync Peer",
                    client_type="server",
                    shared_storage_bytes=20 * 1024 * 1024,
                    free_storage_bytes=20 * 1024 * 1024,
                    accepts_peer_storage=True,
                    web_port=peer_port,
                ))
                owner_app, owner_identity, owner_chunk_store, owner_manifest_store = self.make_node_app(
                    root, name="delete-sync-owner", web_port=_free_tcp_port(), client_type="pc", peer_provider=owner_provider
                )

                with owner_app.test_client() as client:
                    upload_response = client.post(
                        "/upload",
                        data={
                            "folder": DEFAULT_FOLDER,
                            "next": "/",
                            "file": (BytesIO(b"delete synchronization payload " * 40), "delete-sync.txt"),
                        },
                        content_type="multipart/form-data",
                        headers={"X-Requested-With": "XMLHttpRequest"},
                    )
                    self.assertEqual(upload_response.status_code, 200)
                    private_manifest_id = upload_response.json["manifest"]["manifest_id"]
                    private_manifest = owner_manifest_store.load(private_manifest_id)
                    remote_hashes = [
                        str(chunk["hash"])
                        for chunk in private_manifest.chunks
                        if peer_identity.node_id in chunk.get("locations", [])
                    ]
                    self.assertGreater(len(remote_hashes), 0)
                    self.assertTrue(all(peer_chunk_store.chunk_path(digest).exists() for digest in remote_hashes))

                    share_response = client.post(
                        f"/files/{private_manifest_id}/share",
                        data={"next": "/", "shared": "on", "peer_node_id": peer_identity.node_id},
                        headers={"X-Requested-With": "XMLHttpRequest"},
                    )
                    self.assertEqual(share_response.status_code, 200)
                    shared_manifest_id = share_response.json["manifest"]["manifest_id"]
                    shared_payload = owner_manifest_store.load(shared_manifest_id).to_dict()
                    self.assertTrue(peer_manifest_store.path_for(shared_manifest_id).exists())

                    delete_response = client.post(
                        f"/files/{shared_manifest_id}/delete",
                        data={"next": "/"},
                        headers={"X-Requested-With": "XMLHttpRequest"},
                    )

                self.assertEqual(delete_response.status_code, 200)
                self.assertTrue(delete_response.json["ok"])
                self.assertFalse(owner_manifest_store.path_for(shared_manifest_id).exists())
                self.assertFalse(peer_manifest_store.path_for(shared_manifest_id).exists())
                self.assertTrue(all(not peer_chunk_store.chunk_path(digest).exists() for digest in remote_hashes))

                with peer_app.test_client() as peer_client:
                    replay = peer_client.post("/api/p2p/manifests", json=shared_payload)
                self.assertEqual(replay.status_code, 400)
            finally:
                peer_server.stop()


    def test_ajax_settings_update_php_relay_url_and_uses_auto_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)

            with app.test_client() as client:
                response = client.post(
                    "/settings",
                    data={
                        "client_type": "server",
                        "shared_storage_gb": "5",
                        "relay_server_url": "http://127.0.0.1:9/dcloud_relay.php",
                    },
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )

            stop_relays = app.config.get("DCLOUD_STOP_RELAYS")
            if callable(stop_relays):
                stop_relays()
            config = app.config["DCLOUD_APP_CONFIG"]
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json["ok"])
            self.assertEqual(config.network.relay_url, DEFAULT_PUBLIC_RELAY_URL)
            self.assertIn(DEFAULT_PUBLIC_RELAY_URL, config.network.relay_urls)
            self.assertIn("http://127.0.0.1:9/dcloud_relay.php", config.network.relay_urls)
            self.assertEqual(config.network.relay_secret, "")
            self.assertEqual(response.json["settings"]["relayTokenMode"], "automatic-daily")
            self.assertTrue(response.json["state"]["network"]["relayEnabled"])

    def test_dashboard_settings_exposes_php_relay_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            app, identity, manifest_store = self.make_app(root)

            with app.test_client() as client:
                response = client.get("/")

            self.assertEqual(response.status_code, 200)
            self.assertIn(b"settings-relay-url", response.data)
            self.assertIn(b"settings-relay-urls", response.data)
            self.assertIn(b"settings-relay-token-mode", response.data)
            self.assertNotIn(b"settings-relay-secret", response.data)
            self.assertIn("PHP-Relay".encode(), response.data)


if __name__ == "__main__":
    unittest.main()
