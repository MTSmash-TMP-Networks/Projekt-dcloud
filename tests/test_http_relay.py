from pathlib import Path
import json
import shutil
import socket
import subprocess
import tempfile
import time
import threading
import unittest
from urllib import error, request
from unittest.mock import patch

from dcloud_client.identity import IdentityManager
from dcloud_client.network.http_relay import HttpRelayClient, RELAY_HOST, RelayHttpResponse, _decode_relay_json, peer_from_relay_payload
from dcloud_client.network.p2p_storage import P2PStorageClient
from dcloud_client.storage import ChunkStore
from dcloud_client.network.peers import InMemoryPeerProvider, Peer


class FakeRelayClient:
    def __init__(self) -> None:
        self.relay_url = "https://relay.example/dcloud_relay.php"
        self.request_timeout = 1
        self.calls: list[dict[str, object]] = []

    def forward_request(self, peer, *, method, path, headers=None, body=b"", timeout=None):
        self.calls.append({"peer": peer.node_id, "method": method, "path": path, "headers": headers or {}, "body": body})
        if method == "GET":
            return RelayHttpResponse(status_code=200, headers={"Content-Type": "application/octet-stream"}, body=b"stored")
        return RelayHttpResponse(status_code=200, headers={"Content-Type": "application/json"}, body=b'{"ok":true}')


class HttpRelayTests(unittest.TestCase):
    def test_relay_payload_creates_relay_only_peer(self) -> None:
        peer = peer_from_relay_payload(
            {
                "node_id": "peer-node",
                "name": "Remote PC",
                "client_type": "pc",
                "shared_storage_bytes": 5 * 1024**3,
                "free_storage_bytes": 4 * 1024**3,
                "accepts_peer_storage": True,
                "web_port": 8787,
            },
            relay_url="https://relay.example/dcloud_relay.php",
            own_node_id="own-node",
        )

        self.assertIsNotNone(peer)
        assert peer is not None
        self.assertEqual(peer.host, RELAY_HOST)
        self.assertEqual(peer.udp_port, 0)
        self.assertEqual(peer.relay_url, "https://relay.example/dcloud_relay.php")
        self.assertEqual(peer.to_dict()["transport"], "relay")

    def test_peer_provider_keeps_direct_endpoint_and_adds_relay_fallback(self) -> None:
        provider = InMemoryPeerProvider()
        provider.add_or_update(Peer(node_id="peer-node", host="192.168.1.25", udp_port=6881, web_port=8787))
        provider.add_or_update(Peer(node_id="peer-node", host=RELAY_HOST, udp_port=0, relay_url="https://relay.example/dcloud_relay.php"))

        peer = provider.get_peer("peer-node")
        self.assertIsNotNone(peer)
        assert peer is not None
        self.assertEqual(peer.host, "192.168.1.25")
        self.assertEqual(peer.udp_port, 6881)
        self.assertEqual(peer.relay_url, "https://relay.example/dcloud_relay.php")
        self.assertEqual(peer.to_dict()["transport"], "direct+relay")

    def test_p2p_storage_client_uses_relay_for_relay_only_peer(self) -> None:
        relay = FakeRelayClient()
        client = P2PStorageClient(relay_client=relay)  # type: ignore[arg-type]
        peer = Peer(node_id="peer-node", host=RELAY_HOST, udp_port=0, relay_url=relay.relay_url)

        put_result = client.put_chunk(
            peer,
            digest="abc123",
            stored_data=b"stored",
            original_size=6,
            stored_size=6,
            index=0,
            compression=None,
        )
        restored = client.get_chunk(peer, digest="abc123")

        self.assertTrue(put_result.ok)
        self.assertEqual(restored, b"stored")
        self.assertEqual(relay.calls[0]["method"], "POST")
        self.assertEqual(relay.calls[0]["path"], "/api/p2p/chunks/abc123")
        self.assertEqual(relay.calls[1]["method"], "GET")


    def test_relay_client_fetches_daily_token_before_register(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            identity = IdentityManager(Path(temp_dir) / "identity").load_or_create()
            calls: list[dict[str, object]] = []

            class FakeResponse:
                def __init__(self, payload: dict[str, object]) -> None:
                    self.payload = payload

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb) -> None:
                    return None

                def read(self) -> bytes:
                    return json.dumps(self.payload).encode("utf-8")

            def fake_urlopen(req, timeout=0):
                payload = json.loads(req.data.decode("utf-8"))
                calls.append(payload)
                if payload["action"] == "health":
                    return FakeResponse({
                        "ok": True,
                        "relay_token": "daily-token",
                        "relay_token_day": "2026-05-19",
                        "relay_token_expires_at": 4102444800,
                    })
                self.assertEqual(payload["action"], "register")
                self.assertEqual(payload.get("relay_token"), "daily-token")
                return FakeResponse({"ok": True, "peers": [], "relay_urls": []})

            client = HttpRelayClient(relay_url="https://relay.example/dcloud_relay.php", identity=identity)
            with patch("dcloud_client.network.http_relay.request.urlopen", side_effect=fake_urlopen):
                peers = client.register({"name": "Node", "relay_urls": [client.relay_url]})

            self.assertEqual(peers, [])
            self.assertEqual([call["action"] for call in calls], ["health", "register"])
            self.assertEqual(client.access_token, "daily-token")
            self.assertEqual(client.access_token_day, "2026-05-19")


    def test_relay_json_decoder_tolerates_trailing_host_output(self) -> None:
        parsed = _decode_relay_json(b'{"ok":true,"version":"x"}{"ok":false,"message":"old"}', expected_action="health")
        self.assertEqual(parsed, {"ok": True, "version": "x"})

    def test_relay_json_decoder_selects_matching_request_from_concatenated_output(self) -> None:
        raw = (
            b'{"ok":false,"message":"Ungueltige request_id","status":200}'
            b'{"ok":true,"request_id":"wanted"}'
            b'{"ok":true,"request_id":""}'
        )
        parsed = _decode_relay_json(raw, expected_action="enqueue_request", expected_request_id="wanted")
        self.assertEqual(parsed, {"ok": True, "request_id": "wanted"})

    def test_php_relay_filters_invalid_legacy_queue_entries(self) -> None:
        php = shutil.which("php")
        if not php:
            raise unittest.SkipTest("php executable not available")

        relay_source = Path(__file__).resolve().parents[1] / "relay" / "dcloud_relay.php"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "dcloud_relay.php").write_text(relay_source.read_text(encoding="utf-8"), encoding="utf-8")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            url = f"http://127.0.0.1:{port}/dcloud_relay.php"
            proc = subprocess.Popen(
                [php, "-S", f"127.0.0.1:{port}", "dcloud_relay.php"],
                cwd=temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                health = None
                for _ in range(30):
                    try:
                        with request.urlopen(url, timeout=1) as response:
                            health = json.loads(response.read().decode("utf-8"))
                            break
                    except Exception:
                        time.sleep(0.1)
                if not health:
                    raise unittest.SkipTest("php built-in server did not start")
                queue_dir = temp_path / "dcloud-relay-data" / "queues" / "node-test"
                queue_dir.mkdir(parents=True, exist_ok=True)
                (queue_dir / "bad.json").write_text(json.dumps({"request_id": "", "from_node_id": "node-a", "to_node_id": "", "method": "GET", "path": ""}), encoding="utf-8")
                req = request.Request(
                    url,
                    data=json.dumps({
                        "protocol": "dcloud-relay-v1",
                        "action": "poll_requests",
                        "node_id": "node-test",
                        "relay_token": health["relay_token"],
                    }).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    method="POST",
                )
                with request.urlopen(req, timeout=2) as response:
                    raw = response.read().decode("utf-8")
                    body = json.loads(raw)
                self.assertTrue(body.get("ok"), body)
                self.assertEqual(body.get("requests"), [])
                self.assertFalse((queue_dir / "bad.json").exists())

                response_dir = temp_path / "dcloud-relay-data" / "responses"
                response_dir.mkdir(parents=True, exist_ok=True)
                (response_dir / ".json").write_text(json.dumps({"request_id": "", "status_code": 502}), encoding="utf-8")
                req2 = request.Request(
                    url,
                    data=json.dumps({
                        "protocol": "dcloud-relay-v1",
                        "action": "health",
                    }).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    method="POST",
                )
                with request.urlopen(req2, timeout=2) as response:
                    body = json.loads(response.read().decode("utf-8"))
                self.assertTrue(body.get("ok"), body)
                self.assertFalse((response_dir / ".json").exists())
            finally:
                proc.terminate()
                try:
                    proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate(timeout=2)

    def test_php_relay_file_is_packaged(self) -> None:
        relay_file = Path(__file__).resolve().parents[1] / "relay" / "dcloud_relay.php"
        text = relay_file.read_text(encoding="utf-8")
        self.assertIn("dcloud_current_relay_token", text)
        self.assertIn("relay_token", text)
        self.assertIn("enqueue_request", text)
        self.assertIn("poll_response", text)

    def test_php_relay_rejects_null_peer_without_fatal(self) -> None:
        php = shutil.which("php")
        if not php:
            raise unittest.SkipTest("php executable not available")

        relay_source = Path(__file__).resolve().parents[1] / "relay" / "dcloud_relay.php"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "dcloud_relay.php").write_text(relay_source.read_text(encoding="utf-8"), encoding="utf-8")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            url = f"http://127.0.0.1:{port}/dcloud_relay.php"
            proc = subprocess.Popen(
                [php, "-S", f"127.0.0.1:{port}", "dcloud_relay.php"],
                cwd=temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                health: dict[str, object] | None = None
                for _ in range(30):
                    if proc.poll() is not None:
                        break
                    try:
                        with request.urlopen(url, timeout=1) as response:
                            health = json.loads(response.read().decode("utf-8"))
                            break
                    except Exception:
                        time.sleep(0.1)
                if not health:
                    stderr = proc.stderr.read() if proc.stderr else ""
                    raise unittest.SkipTest(f"php built-in server did not start: {stderr}")
                self.assertTrue(health.get("ok"))
                token = str(health.get("relay_token"))
                payload = {
                    "protocol": "dcloud-relay-v1",
                    "action": "register",
                    "node_id": "node-test",
                    "relay_token": token,
                    "peer": None,
                }
                req = request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    method="POST",
                )
                with request.urlopen(req, timeout=2) as response:
                    self.assertEqual(response.status, 200)
                    body = json.loads(response.read().decode("utf-8"))
                self.assertTrue(body.get("ok"), body)
                self.assertIn("peers", body)
            finally:
                proc.terminate()
                try:
                    proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate(timeout=2)

    def test_php_relay_file_contains_hardening_guards(self) -> None:
        relay_file = Path(__file__).resolve().parents[1] / "relay" / "dcloud_relay.php"
        text = relay_file.read_text(encoding="utf-8")
        self.assertIn("catch (Throwable $exception)", text)
        self.assertIn("function dcloud_sanitize_peer($peer", text)
        self.assertIn("Register ohne peer-Metadaten", text)
        self.assertIn("GET unterstuetzt nur die Relay-Health-Abfrage", text)

    def test_php_relay_returns_json_ok_false_instead_of_http_400_for_bad_action(self) -> None:
        php = shutil.which("php")
        if not php:
            raise unittest.SkipTest("php executable not available")

        relay_source = Path(__file__).resolve().parents[1] / "relay" / "dcloud_relay.php"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "dcloud_relay.php").write_text(relay_source.read_text(encoding="utf-8"), encoding="utf-8")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            url = f"http://127.0.0.1:{port}/dcloud_relay.php"
            proc = subprocess.Popen(
                [php, "-S", f"127.0.0.1:{port}", "dcloud_relay.php"],
                cwd=temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                for _ in range(30):
                    try:
                        with request.urlopen(url, timeout=1) as response:
                            health = json.loads(response.read().decode("utf-8"))
                            break
                    except Exception:
                        time.sleep(0.1)
                else:
                    raise unittest.SkipTest("php built-in server did not start")
                req = request.Request(
                    url,
                    data=json.dumps({
                        "protocol": "dcloud-relay-v1",
                        "action": "does_not_exist",
                        "node_id": "node-test",
                        "relay_token": health["relay_token"],
                    }).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    method="POST",
                )
                with request.urlopen(req, timeout=2) as response:
                    self.assertEqual(response.status, 200)
                    body = json.loads(response.read().decode("utf-8"))
                self.assertFalse(body.get("ok", True))
                self.assertIn("Unbekannte Relay-Aktion", str(body.get("message", "")))
            finally:
                proc.terminate()
                try:
                    proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate(timeout=2)


    def test_relay_client_sends_target_node_compatibility_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            identity = IdentityManager(Path(temp_dir) / "identity").load_or_create()
            captured: list[dict[str, object]] = []

            class FakeResponse:
                def __init__(self, payload: dict[str, object]) -> None:
                    self.payload = payload

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb) -> None:
                    return None

                def read(self) -> bytes:
                    return json.dumps(self.payload).encode("utf-8")

            def fake_urlopen(req, timeout=0):
                payload = json.loads(req.data.decode("utf-8"))
                captured.append(payload)
                action = payload.get("action")
                if action == "health":
                    return FakeResponse({"ok": True, "relay_token": "daily-token", "relay_token_expires_at": 4102444800})
                if action == "enqueue_request":
                    self.assertEqual(payload.get("to_node_id"), "peer-node")
                    self.assertEqual(payload.get("target_node_id"), "peer-node")
                    self.assertEqual(payload.get("request_id"), payload.get("relay_request_id"))
                    return FakeResponse({"ok": True, "request_id": payload["request_id"]})
                if action == "poll_response":
                    self.assertEqual(payload.get("request_id"), payload.get("relay_request_id"))
                    return FakeResponse({"ok": True, "ready": True, "response": {"request_id": payload["request_id"], "status_code": 200, "headers": {}, "body_base64": ""}})
                raise AssertionError(action)

            client = HttpRelayClient(relay_url="https://relay.example/dcloud_relay.php", identity=identity, request_timeout=0.2)
            peer = Peer(node_id="peer-node", host=RELAY_HOST, udp_port=0, relay_url=client.relay_url)
            with patch("dcloud_client.network.http_relay.request.urlopen", side_effect=fake_urlopen):
                response = client.forward_request(peer, method="GET", path="/api/p2p/chunks/abc")

            self.assertEqual(response.status_code, 200)
            self.assertIn("enqueue_request", [item.get("action") for item in captured])

    def test_php_relay_accepts_target_node_alias_for_enqueue(self) -> None:
        php = shutil.which("php")
        if not php:
            raise unittest.SkipTest("php executable not available")

        relay_source = Path(__file__).resolve().parents[1] / "relay" / "dcloud_relay.php"
        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / "dcloud_relay.php").write_text(relay_source.read_text(encoding="utf-8"), encoding="utf-8")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            url = f"http://127.0.0.1:{port}/dcloud_relay.php"
            proc = subprocess.Popen([php, "-S", f"127.0.0.1:{port}", "dcloud_relay.php"], cwd=temp_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                health = None
                for _ in range(30):
                    try:
                        with request.urlopen(url, timeout=1) as response:
                            health = json.loads(response.read().decode("utf-8"))
                            break
                    except Exception:
                        time.sleep(0.1)
                if not health:
                    raise unittest.SkipTest("php built-in server did not start")

                enqueue = request.Request(
                    url,
                    data=json.dumps({
                        "protocol": "dcloud-relay-v1",
                        "action": "enqueue_request",
                        "node_id": "node-a",
                        "target_node_id": "node-b",
                        "relay_request_id": "req-1",
                        "method": "GET",
                        "path": "/api/p2p/chunks/abc",
                        "headers": {},
                        "body_base64": "",
                        "relay_token": health["relay_token"],
                    }).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    method="POST",
                )
                with request.urlopen(enqueue, timeout=2) as response:
                    body = json.loads(response.read().decode("utf-8"))
                self.assertTrue(body.get("ok"), body)
                self.assertEqual(body.get("request_id"), "req-1")
                self.assertEqual(body.get("to_node_id"), "node-b")

                poll = request.Request(
                    url,
                    data=json.dumps({
                        "protocol": "dcloud-relay-v1",
                        "action": "poll_requests",
                        "node_id": "node-b",
                        "relay_token": health["relay_token"],
                    }).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    method="POST",
                )
                with request.urlopen(poll, timeout=2) as response:
                    body = json.loads(response.read().decode("utf-8"))
                self.assertTrue(body.get("ok"), body)
                self.assertEqual(body.get("requests", [])[0]["request_id"], "req-1")
            finally:
                proc.terminate()
                try:
                    proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate(timeout=2)

    def test_relay_upload_uses_small_chunks_for_relay_peers(self) -> None:
        from dcloud_client.network.p2p_storage import distribute_file_chunks

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "large.bin"
            source.write_bytes(b"x" * (1024 * 1024 + 123))
            store = ChunkStore(root / "storage", limit_bytes=20 * 1024 * 1024, min_free_bytes=0, chunk_size=4 * 1024 * 1024)
            store.initialize()

            class RecordingP2P:
                def __init__(self) -> None:
                    self.sizes: list[int] = []
                def put_chunk(self, peer, *, digest, stored_data, original_size, stored_size, index, compression):
                    self.sizes.append(len(stored_data))
                    return type("Result", (), {"ok": True})()

            p2p = RecordingP2P()
            peer = Peer(node_id="peer-node", host=RELAY_HOST, udp_port=0, relay_url="https://relay.example/dcloud_relay.php")
            result = distribute_file_chunks(
                source_path=source,
                chunk_store=store,
                local_node_id="local-node",
                peers=[peer],
                p2p_client=p2p,  # type: ignore[arg-type]
                chunk_size_bytes=512 * 1024,
            )

            self.assertGreater(len(result.chunks), 1)
            self.assertTrue(p2p.sizes)
            self.assertTrue(all(size <= 512 * 1024 for size in p2p.sizes))
            self.assertEqual(result.remote_failures, 0)
            self.assertEqual(result.remote_successes, len(result.chunks))


    def test_php_relay_register_does_not_fall_through_to_proxy_validation(self) -> None:
        php = shutil.which("php")
        if not php:
            raise unittest.SkipTest("php executable not available")

        relay_source = Path(__file__).resolve().parents[1] / "relay" / "dcloud_relay.php"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "dcloud_relay.php").write_text(relay_source.read_text(encoding="utf-8"), encoding="utf-8")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            url = f"http://127.0.0.1:{port}/dcloud_relay.php"
            proc = subprocess.Popen([php, "-S", f"127.0.0.1:{port}", "dcloud_relay.php"], cwd=temp_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                health = None
                for _ in range(30):
                    try:
                        with request.urlopen(url, timeout=1) as response:
                            health = json.loads(response.read().decode("utf-8"))
                            break
                    except Exception:
                        time.sleep(0.1)
                if not health:
                    raise unittest.SkipTest("php built-in server did not start")

                register = request.Request(
                    url,
                    data=json.dumps({
                        "protocol": "dcloud-relay-v1",
                        "action": "register",
                        "node_id": "node-a",
                        "relay_token": health["relay_token"],
                        "peer": {
                            "node_id": "node-a",
                            "name": "Node A",
                            "protocol_magic": "DCLOUD1",
                            "accepts_peer_storage": True,
                            "relay_urls": [url],
                        },
                    }).encode("utf-8"),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    method="POST",
                )
                with request.urlopen(register, timeout=2) as response:
                    body = json.loads(response.read().decode("utf-8"))
                self.assertTrue(body.get("ok"), body)
                log_path = temp_path / "dcloud-relay-data" / "relay-events.log"
                log_text = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
                self.assertNotIn("Relay-Anfrage ist unvollstaendig", log_text)
                self.assertNotIn("Nur GET/POST auf /api/p2p/", log_text)
            finally:
                proc.terminate()
                try:
                    proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate(timeout=2)


if __name__ == "__main__":
    unittest.main()

class HttpRelayEndToEndTests(unittest.TestCase):
    def test_relay_forward_request_waits_for_delayed_peer_response(self) -> None:
        php = shutil.which("php")
        if not php:
            raise unittest.SkipTest("php executable not available")
        relay_source = Path(__file__).resolve().parents[1] / "relay" / "dcloud_relay.php"
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as ida, tempfile.TemporaryDirectory() as idb:
            temp_path = Path(temp_dir)
            (temp_path / "dcloud_relay.php").write_text(relay_source.read_text(encoding="utf-8"), encoding="utf-8")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            url = f"http://127.0.0.1:{port}/dcloud_relay.php"
            proc = subprocess.Popen(
                [php, "-S", f"127.0.0.1:{port}", "dcloud_relay.php"],
                cwd=temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                for _ in range(30):
                    try:
                        with request.urlopen(url, timeout=1) as response:
                            health = json.loads(response.read().decode("utf-8"))
                            break
                    except Exception:
                        time.sleep(0.1)
                else:
                    raise unittest.SkipTest("php built-in server did not start")

                identity_a = IdentityManager(Path(ida) / "identity").load_or_create()
                identity_b = IdentityManager(Path(idb) / "identity").load_or_create()
                client_a = HttpRelayClient(relay_url=url, identity=identity_a, timeout=2, request_timeout=10)
                client_b = HttpRelayClient(relay_url=url, identity=identity_b, timeout=2, request_timeout=10)
                client_b.register({
                    "node_id": identity_b.node_id,
                    "name": "Peer B",
                    "client_type": "pc",
                    "accepts_peer_storage": True,
                    "shared_storage_bytes": 5 * 1024**3,
                    "free_storage_bytes": 5 * 1024**3,
                    "relay_urls": [url],
                })
                peers = client_a.register({
                    "node_id": identity_a.node_id,
                    "name": "Peer A",
                    "client_type": "pc",
                    "accepts_peer_storage": True,
                    "shared_storage_bytes": 5 * 1024**3,
                    "free_storage_bytes": 5 * 1024**3,
                    "relay_urls": [url],
                })
                peer_b = next(peer for peer in peers if peer.node_id == identity_b.node_id)

                def delayed_worker() -> None:
                    # Simulate a slow remote client / PHP host. The uploader must
                    # keep polling instead of immediately falling back to local-only.
                    time.sleep(1.0)
                    envelopes = client_b.poll_requests(max_requests=8, wait_seconds=3)
                    self.assertEqual(len(envelopes), 1)
                    client_b.post_response(
                        envelopes[0]["request_id"],
                        RelayHttpResponse(status_code=200, headers={"Content-Type": "application/json"}, body=b'{"ok":true}'),
                    )

                worker = threading.Thread(target=delayed_worker)
                worker.start()
                response = client_a.forward_request(peer_b, method="POST", path="/api/p2p/chunks/abc", body=b"chunk")
                worker.join(timeout=5)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.body, b'{"ok":true}')
            finally:
                proc.terminate()
                try:
                    proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate(timeout=2)
