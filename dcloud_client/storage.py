"""Content-addressed chunk storage."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
import shutil
import tempfile
import zlib
from typing import Any, BinaryIO, Iterable


class StorageError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ChunkInfo:
    hash: str
    size: int
    path: Path
    index: int
    stored_size: int | None = None
    compression: str | None = None


@dataclass(frozen=True, slots=True)
class StorageStats:
    path: Path
    limit_bytes: int
    used_bytes: int
    free_limit_bytes: int
    filesystem_free_bytes: int
    min_free_bytes: int


class ChunkStore:
    """Stores chunks by SHA-256 hash with atomic writes.

    Chunks are addressed by the hash of the bytes that are actually stored on
    disk. In normal operation these bytes may already be compressed. This makes
    local storage, peer transfer and later integrity checks use the exact same
    digest.
    """

    def __init__(self, root: Path, limit_bytes: int, min_free_bytes: int, chunk_size: int) -> None:
        self.root = root
        self.chunks_dir = root / "chunks"
        self.manifests_dir = root / "manifests"
        self.tmp_dir = root / "tmp"
        self.downloads_dir = root / "downloads"
        self.limit_bytes = limit_bytes
        self.min_free_bytes = min_free_bytes
        self.chunk_size = chunk_size

    def initialize(self) -> None:
        for directory in (self.root, self.chunks_dir, self.manifests_dir, self.tmp_dir, self.downloads_dir):
            directory.mkdir(parents=True, exist_ok=True)

    def chunk_path(self, digest: str) -> Path:
        return self.chunks_dir / digest[:2] / f"{digest}.chunk"

    def stats(self) -> StorageStats:
        used = self.used_bytes()
        filesystem_free = shutil.disk_usage(self.root).free if self.root.exists() else 0
        return StorageStats(
            path=self.root,
            limit_bytes=self.limit_bytes,
            used_bytes=used,
            free_limit_bytes=max(self.limit_bytes - used, 0),
            filesystem_free_bytes=filesystem_free,
            min_free_bytes=self.min_free_bytes,
        )

    def used_bytes(self) -> int:
        """Return used bytes while tolerating concurrent chunk cleanup.

        Peer delete/revocation requests can remove chunk files and the two-letter
        chunk subdirectories while another request is building /api/state or
        refreshing advertised free storage. pathlib.Path.rglob() raises
        FileNotFoundError when a directory disappears after it has been listed but
        before it is scanned. For a running P2P node that race is expected, so
        storage accounting treats disappeared files/directories as already gone.
        """
        total = 0

        def ignore_missing_directory(_error: OSError) -> None:
            # os.walk calls this when a directory vanishes during traversal.
            # The file is already deleted, so it should count as 0 bytes.
            return None

        for directory in (self.chunks_dir, self.manifests_dir):
            if not directory.exists():
                continue
            for current_root, _dirs, files in os.walk(directory, onerror=ignore_missing_directory):
                for file_name in files:
                    file_path = Path(current_root) / file_name
                    try:
                        if file_path.is_file():
                            total += file_path.stat().st_size
                    except FileNotFoundError:
                        # A concurrent peer cleanup removed the file after os.walk
                        # listed it. Skip it and keep the API/state request alive.
                        continue
                    except OSError:
                        # Permission or transient filesystem issues on a single
                        # file should not break the whole node status endpoint.
                        continue
        return total

    def ensure_capacity(self, additional_bytes: int) -> None:
        stats = self.stats()
        if stats.used_bytes + additional_bytes > self.limit_bytes:
            raise StorageError("Configured storage limit would be exceeded")
        if stats.filesystem_free_bytes - additional_bytes < self.min_free_bytes:
            raise StorageError("Minimum filesystem free space would be undercut")

    def prepare_chunk_data(self, data: bytes) -> tuple[bytes, str | None]:
        """Return the bytes to store and the compression marker for a raw chunk."""
        compressed = zlib.compress(data)
        if len(compressed) < len(data):
            return compressed, "zlib"
        return data, None

    # Backwards-compatible internal name used by earlier code.
    def _prepare_chunk_data(self, data: bytes) -> tuple[bytes, str | None]:
        return self.prepare_chunk_data(data)

    @staticmethod
    def digest_for_stored_data(stored_data: bytes) -> str:
        return hashlib.sha256(stored_data).hexdigest()

    def _validate_stored_chunk(self, stored_data: bytes, original_size: int, compression: str | None) -> None:
        if compression is None:
            if original_size != len(stored_data):
                # This is not fatal for old manifests, but for peer uploads it
                # catches malformed metadata before it is persisted.
                raise StorageError("Chunk metadata does not match uncompressed chunk size")
            return
        if compression == "zlib":
            try:
                raw = zlib.decompress(stored_data)
            except zlib.error as exc:
                raise StorageError("Compressed chunk cannot be decompressed") from exc
            if len(raw) != int(original_size):
                raise StorageError("Compressed chunk metadata reports the wrong original size")
            return
        raise StorageError(f"Unsupported chunk compression {compression}")

    def write_stored_chunk(
        self,
        stored_data: bytes,
        *,
        original_size: int,
        index: int = 0,
        compression: str | None = None,
        digest: str | None = None,
        validate: bool = True,
    ) -> ChunkInfo:
        """Persist bytes that are already in their on-disk/transfer format.

        This is used by the peer-to-peer storage API: the receiving peer stores
        exactly the compressed bytes whose hash is written into the manifest.
        """
        if validate:
            self._validate_stored_chunk(stored_data, original_size, compression)
        actual_digest = self.digest_for_stored_data(stored_data)
        if digest is not None and actual_digest != digest:
            raise StorageError(f"Chunk hash mismatch for {digest}")
        target = self.chunk_path(actual_digest)
        if target.exists():
            return ChunkInfo(
                hash=actual_digest,
                size=int(original_size),
                path=target,
                index=index,
                stored_size=len(stored_data),
                compression=compression,
            )

        self.ensure_capacity(len(stored_data))
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix="chunk-", suffix=".tmp", dir=self.tmp_dir)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(stored_data)
                handle.flush()
                os.fsync(handle.fileno())
            Path(tmp_name).replace(target)
        except Exception:
            Path(tmp_name).unlink(missing_ok=True)
            raise
        return ChunkInfo(
            hash=actual_digest,
            size=int(original_size),
            path=target,
            index=index,
            stored_size=len(stored_data),
            compression=compression,
        )

    def write_chunk(self, data: bytes, index: int = 0) -> ChunkInfo:
        stored_data, compression = self.prepare_chunk_data(data)
        return self.write_stored_chunk(
            stored_data,
            original_size=len(data),
            index=index,
            compression=compression,
            validate=False,
        )

    def chunk_file(self, source: BinaryIO) -> list[ChunkInfo]:
        chunks: list[ChunkInfo] = []
        index = 0
        while True:
            data = source.read(self.chunk_size)
            if not data:
                break
            chunks.append(self.write_chunk(data, index=index))
            index += 1
        return chunks

    def read_stored_chunk(self, digest: str) -> bytes:
        path = self.chunk_path(digest)
        if not path.exists():
            raise StorageError(f"Missing chunk {digest}")
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise StorageError(f"Chunk hash mismatch for {digest}")
        return data

    def read_chunk(self, digest: str, compression: str | None = None) -> bytes:
        data = self.read_stored_chunk(digest)
        if compression is None:
            return data
        if compression == "zlib":
            return zlib.decompress(data)
        raise StorageError(f"Unsupported chunk compression {compression}")

    def restore_chunks(self, chunk_hashes: Iterable[str | dict[str, Any]], target: Path) -> Path:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix="restore-", suffix=".tmp", dir=self.tmp_dir)
        try:
            with os.fdopen(fd, "wb") as handle:
                for chunk in chunk_hashes:
                    if isinstance(chunk, dict):
                        digest = str(chunk["hash"])
                        compression = chunk.get("compression")
                        handle.write(self.read_chunk(digest, str(compression) if compression else None))
                    else:
                        handle.write(self.read_chunk(chunk))
                handle.flush()
                os.fsync(handle.fileno())
            Path(tmp_name).replace(target)
        except Exception:
            Path(tmp_name).unlink(missing_ok=True)
            raise
        return target
