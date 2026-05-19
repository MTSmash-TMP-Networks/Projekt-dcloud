from pathlib import Path
import tempfile
import unittest

from dcloud_client import storage as storage_module
from dcloud_client.identity import IdentityManager
from dcloud_client.manifests import ManifestStore
from dcloud_client.storage import ChunkStore


class StorageManifestTests(unittest.TestCase):
    def make_store(self, root: Path) -> tuple[ChunkStore, ManifestStore]:
        chunk_store = ChunkStore(root, limit_bytes=20 * 1024 * 1024, min_free_bytes=0, chunk_size=64)
        chunk_store.initialize()
        return chunk_store, ManifestStore(chunk_store)

    def test_compressed_chunks_restore_original_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            identity = IdentityManager(root / "identity").load_or_create()
            chunk_store, manifest_store = self.make_store(root / "storage")
            source = root / "payload.txt"
            payload = (b"aaaaabbbbbccccc" * 100)
            source.write_bytes(payload)

            manifest = manifest_store.create_for_file(source, identity, peer_node_ids=["peer-a", "peer-b"])
            self.assertTrue(any(chunk.get("compression") == "zlib" for chunk in manifest.chunks))
            self.assertEqual(manifest.placement["targets"], [identity.node_id, "peer-a", "peer-b"])

            restored = manifest_store.restore(manifest.manifest_id, root / "restored.txt")
            self.assertEqual(restored.read_bytes(), payload)

    def test_delete_removes_manifest_and_unreferenced_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            identity = IdentityManager(root / "identity").load_or_create()
            chunk_store, manifest_store = self.make_store(root / "storage")
            source = root / "payload.txt"
            source.write_bytes(b"delete me" * 100)

            manifest = manifest_store.create_for_file(source, identity)
            chunk_paths = [chunk_store.chunk_path(str(chunk["hash"])) for chunk in manifest.chunks]
            self.assertTrue(all(path.exists() for path in chunk_paths))

            manifest_store.delete(manifest.manifest_id)

            self.assertFalse(manifest_store.path_for(manifest.manifest_id).exists())
            self.assertTrue(all(not path.exists() for path in chunk_paths))

    def test_stats_tolerates_chunk_directory_removed_during_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            chunk_store, _ = self.make_store(root / "storage")
            vanished_dir = chunk_store.chunks_dir / "0b"
            vanished_dir.mkdir(parents=True, exist_ok=True)
            (vanished_dir / "vanished.chunk").write_bytes(b"data")

            original_walk = storage_module.os.walk

            def racing_walk(directory, *args, **kwargs):
                if Path(directory) == chunk_store.chunks_dir:
                    onerror = kwargs.get("onerror")
                    if onerror is not None:
                        onerror(FileNotFoundError(str(vanished_dir)))
                    if False:
                        yield None
                    return
                yield from original_walk(directory, *args, **kwargs)

            try:
                storage_module.os.walk = racing_walk
                stats = chunk_store.stats()
            finally:
                storage_module.os.walk = original_walk

            self.assertGreaterEqual(stats.used_bytes, 0)


if __name__ == "__main__":
    unittest.main()
