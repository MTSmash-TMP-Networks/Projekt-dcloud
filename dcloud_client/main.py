"""Command-line entry point for the dcloud client MVP."""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import threading
import time
from contextlib import closing
from pathlib import Path

if __package__ in {None, ""}:
    # Support ``python main.py`` after cd'ing into the package directory.
    # Relative imports below still run as package imports once the project root
    # is on sys.path and __package__ identifies the package name.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "dcloud_client"

from .config import AppConfig, load_config
from .identity import IdentityManager
from .manifests import DEFAULT_FOLDER, ManifestStore, sanitize_folder_path
from .network.peers import InMemoryPeerProvider
from .network.smb_server import EmbeddedSmbServer
from .network.udp_discovery import UdpDiscoveryTransport
from .storage import ChunkStore
from .web.app import create_app

LOG = logging.getLogger(__name__)


def configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def choose_udp_port(config: AppConfig) -> int:
    candidates = [config.network.udp_port] + [
        port for port in range(config.network.udp_port_range.start, config.network.udp_port_range.end + 1) if port != config.network.udp_port
    ]
    for port in candidates:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            try:
                sock.bind((config.network.udp_host, port))
                return port
            except OSError:
                LOG.warning("UDP port %s is unavailable, trying next candidate", port)
    raise RuntimeError("No UDP port available in configured range")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="dcloud decentralized storage client MVP")
    parser.add_argument("--config", default="config.yml", help="Path to config.yml")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    configure_logging(args.verbose)
    config = load_config(args.config)

    chunk_store = ChunkStore(
        root=config.storage.path,
        limit_bytes=config.storage.limit_bytes,
        min_free_bytes=config.storage.min_free_bytes,
        chunk_size=config.storage.chunk_size_bytes,
    )
    chunk_store.initialize()

    identity = IdentityManager(config.node.identity_path).load_or_create()
    manifest_store = ManifestStore(chunk_store)
    peer_provider = InMemoryPeerProvider(peer_timeout_seconds=config.network.peer_timeout_seconds)

    udp_port = choose_udp_port(config)
    discovery = UdpDiscoveryTransport(
        host=config.network.udp_host,
        port=udp_port,
        protocol_magic=config.security.protocol_magic,
        identity=identity,
        node_name=config.node.name,
        peer_provider=peer_provider,
        bootstrap_nodes=config.network.bootstrap_nodes,
        tree_parent_nodes=config.network.tree_parent_nodes,
        relay_children=config.network.relay_children,
        discovery_interval_seconds=config.network.discovery_interval_seconds,
        auto_discovery_enabled=config.network.auto_discovery_enabled,
        auto_discovery_ports=config.network.auto_discovery_ports,
        auto_discovery_hosts=config.network.auto_discovery_hosts,
        startup_discovery_seconds=config.network.startup_discovery_seconds,
        startup_discovery_interval_seconds=config.network.startup_discovery_interval_seconds,
        peer_timeout_seconds=config.network.peer_timeout_seconds,
        peer_cleanup_interval_seconds=config.network.peer_cleanup_interval_seconds,
        client_type=config.node.client_type,
        shared_storage_bytes=config.storage.limit_bytes,
        free_storage_bytes=chunk_store.stats().free_limit_bytes,
        web_port=config.web.port,
        relay_urls=config.network.relay_urls,
    )
    discovery.start()

    smb_server = None
    smb_thread = None
    smb_sync_thread = None
    smb_sync_stop = threading.Event()
    smb_root = config.storage.path / "smb_virtual"
    smb_status: dict[str, object] = {"enabled": bool(config.smb.enabled), "running": False, "port": int(config.smb.port), "last_error": ""}
    if config.smb.enabled:
        smb_server = EmbeddedSmbServer(
            root=smb_root,
            host=config.smb.host,
            port=config.smb.port,
            share_name=config.smb.share_name,
            username=config.smb.username,
            password=config.smb.password,
        )
        def run_smb_server() -> None:
            try:
                smb_server.start()
            except Exception as exc:
                smb_status["running"] = False
                smb_status["last_error"] = str(exc)
                LOG.exception("Embedded SMB server konnte nicht gestartet werden")
            else:
                smb_status["running"] = bool(smb_server.running)
                smb_status["port"] = int(smb_server.actual_port)
                smb_status["last_error"] = ""

        smb_thread = threading.Thread(target=run_smb_server, name="dcloud-smb", daemon=True)
        smb_thread.start()
        smb_status["running"] = bool(smb_server.running)
        smb_status["port"] = int(smb_server.actual_port)
        smb_status["last_error"] = smb_server.last_error

        def sync_smb_virtual_view() -> None:
            previous_expected: set[Path] = set()
            while not smb_sync_stop.is_set():
                try:
                    manifests = manifest_store.list_visible_for_node(identity.node_id)
                    smb_root.mkdir(parents=True, exist_ok=True)
                    expected: set[Path] = set()
                    manifest_by_virtual_path: dict[Path, object] = {}
                    for manifest in manifests:
                        folder = Path(manifest.folder_path or DEFAULT_FOLDER)
                        target_dir = smb_root / folder
                        target_dir.mkdir(parents=True, exist_ok=True)
                        target_file = target_dir / manifest.file_name
                        expected.add(target_file.resolve())
                        manifest_by_virtual_path[target_file.resolve()] = manifest
                        if target_file.exists() and target_file.stat().st_size == int(manifest.file_size):
                            continue
                        try:
                            manifest_store.restore(manifest.manifest_id, target=target_file)
                        except Exception:
                            LOG.debug("SMB-View Sync: Restore für %s fehlgeschlagen", manifest.manifest_id, exc_info=True)
                            continue
                    existing_files = [p for p in smb_root.rglob("*") if p.is_file()]
                    for existing in existing_files:
                        resolved = existing.resolve()
                        manifest = manifest_by_virtual_path.get(resolved)
                        if manifest is None:
                            if resolved in previous_expected:
                                # Diese Datei wurde im vorherigen Sync noch von einem Manifest
                                # abgedeckt, inzwischen aber gelöscht (z. B. via UI). In diesem
                                # Fall darf sie nicht als neue SMB-Datei re-importiert werden.
                                existing.unlink(missing_ok=True)
                                continue
                            # Neue Datei via SMB angelegt -> als neues Manifest importieren
                            rel = resolved.relative_to(smb_root.resolve())
                            folder_path = sanitize_folder_path(str(rel.parent).replace("\\", "/"))
                            try:
                                manifest_store.create_for_file(existing, identity, folder_path=folder_path or DEFAULT_FOLDER)
                            except Exception:
                                LOG.debug("SMB-View Sync: Import fehlgeschlagen für %s", existing, exc_info=True)
                            continue
                        if existing.stat().st_size != int(manifest.file_size):
                            # Datei via SMB geändert -> altes Manifest ersetzen
                            try:
                                manifest_store.delete(manifest.manifest_id, delete_unreferenced_chunks=True)
                                rel = resolved.relative_to(smb_root.resolve())
                                folder_path = sanitize_folder_path(str(rel.parent).replace("\\", "/"))
                                manifest_store.create_for_file(existing, identity, folder_path=folder_path or DEFAULT_FOLDER)
                            except Exception:
                                LOG.debug("SMB-View Sync: Update fehlgeschlagen für %s", existing, exc_info=True)
                    # Datei via SMB gelöscht -> zugehöriges Manifest löschen
                    for virtual_path, manifest in manifest_by_virtual_path.items():
                        if not virtual_path.exists():
                            try:
                                manifest_store.delete(manifest.manifest_id, delete_unreferenced_chunks=True)
                            except Exception:
                                LOG.debug("SMB-View Sync: Delete fehlgeschlagen für %s", manifest.manifest_id, exc_info=True)
                    for existing in smb_root.rglob("*"):
                        if existing.is_file() and existing.resolve() not in expected:
                            existing.unlink(missing_ok=True)
                    for existing_dir in sorted([p for p in smb_root.rglob("*") if p.is_dir()], reverse=True):
                        try:
                            existing_dir.rmdir()
                        except OSError:
                            pass
                except Exception:
                    LOG.debug("SMB-View Sync fehlgeschlagen", exc_info=True)
                previous_expected = set(expected) if "expected" in locals() else set()
                smb_sync_stop.wait(5.0)

        smb_sync_thread = threading.Thread(target=sync_smb_virtual_view, name="dcloud-smb-sync", daemon=True)
        smb_sync_thread.start()

    config.network.udp_port = udp_port
    app = create_app(config, identity, chunk_store, manifest_store, peer_provider, discovery)
    app.config["DCLOUD_SMB_STATUS"] = smb_status
    app.config["DCLOUD_SMB_SERVER"] = smb_server
    app.config["DCLOUD_SMB_ROOT"] = str(smb_root)
    LOG.info("Starting local web UI on http://%s:%s", config.web.host, config.web.port)
    try:
        app.run(host=config.web.host, port=config.web.port, threaded=True)
    finally:
        stop_relays = app.config.get("DCLOUD_STOP_RELAYS")
        if callable(stop_relays):
            stop_relays()
        if smb_server is not None:
            smb_sync_stop.set()
            smb_server.stop()
        discovery.stop()


if __name__ == "__main__":
    main()
