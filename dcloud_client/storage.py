"""Content-addressed chunk storage."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
import shutil
import tempfile
import zlib
from typing import Any, BinaryIO, Callable, Iterable

try:
    import zstandard as zstd  # type: ignore
except Exception:  # pragma: no cover - optional runtime dependency
    zstd = None


class StorageError(RuntimeError):
    pass


COMPRESSED_FILE_EXTENSIONS = {
    ".7z", ".avi", ".br", ".bz2", ".dmg", ".gz", ".heic", ".heif",
    ".iso", ".jar", ".jpeg", ".jpg", ".lz4", ".m4a", ".mkv",
    ".mov", ".mp3", ".mp4", ".ogg", ".pdf", ".png", ".rar",
    ".tgz", ".webm", ".webp", ".xz", ".zip", ".zst",
}


@dataclass(frozen=True)
class ChunkInfo:
    hash: str
    size: int
    path: Path
    index: int
    stored_size: int | None = None
    compression: str | None = None


@dataclass(frozen=True)
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

    def __init__(
        self,
        root: Path,
        limit_bytes: int,
        min_free_bytes: int,
        chunk_size: int,
        *,
        compression_mode: str = "auto",
        compression_algorithm: str = "auto",
        compression_level: int = 1,
        compression_min_savings_percent: float = 3.0,
        compression_min_savings_bytes: int = 64 * 1024,
        compression_skip_incompressible: bool = True,
    ) -> None:
        self.root = root
        self.chunks_dir = root / "chunks"
        self.manifests_dir = root / "manifests"
        self.tmp_dir = root / "tmp"
        self.downloads_dir = root / "downloads"
        self.limit_bytes = limit_bytes
        self.min_free_bytes = min_free_bytes
        self.chunk_size = chunk_size
        self.configure_compression(
            mode=compression_mode,
            algorithm=compression_algorithm,
            level=compression_level,
            min_savings_percent=compression_min_savings_percent,
            min_savings_bytes=compression_min_savings_bytes,
            skip_incompressible=compression_skip_incompressible,
        )

    def configure_compression(
        self,
        *,
        mode: str = "auto",
        algorithm: str = "auto",
        level: int = 1,
        min_savings_percent: float = 3.0,
        min_savings_bytes: int = 64 * 1024,
        skip_incompressible: bool = True,
    ) -> None:
        self.compression_mode = str(mode or "auto").lower()
        self.compression_algorithm = str(algorithm or "auto").lower()
        self.compression_level = max(1, min(22, int(level or 1)))
        self.compression_min_savings_percent = max(0.0, float(min_savings_percent or 0.0))
        self.compression_min_savings_bytes = max(0, int(min_savings_bytes or 0))
        self.compression_skip_incompressible = bool(skip_incompressible)

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

    def _compression_level_for_mode(self) -> int:
        mode = self.compression_mode
        if mode == "fast":
            return 1
        if mode == "balanced":
            return 3
        if mode == "max":
            return 10
        return self.compression_level

    def _selected_compression_algorithm(self) -> str | None:
        mode = self.compression_mode
        if mode in {"off", "none", "disabled"}:
            return None
        algorithm = self.compression_algorithm
        if algorithm in {"off", "none", "disabled"}:
            return None
        if algorithm == "zstd" and zstd is not None:
            return "zstd"
        if algorithm == "zstd" and zstd is None:
            return "zlib"
        if algorithm == "zlib":
            return "zlib"
        # auto keeps the network-compatible zlib behavior. zstd can be enabled
        # explicitly once all storage peers have the optional zstandard package.
        return "zlib"

    @staticmethod
    def _looks_like_precompressed_file(file_name: str | None) -> bool:
        if not file_name:
            return False
        return Path(str(file_name)).suffix.lower() in COMPRESSED_FILE_EXTENSIONS

    def _compress_with_algorithm(self, data: bytes, algorithm: str, *, level: int | None = None) -> bytes:
        effective_level = int(level if level is not None else self._compression_level_for_mode())
        if algorithm == "zstd" and zstd is not None:
            return zstd.ZstdCompressor(level=effective_level).compress(data)
        if algorithm == "zlib":
            return zlib.compress(data, max(1, min(9, effective_level)))
        raise StorageError(f"Unsupported chunk compression {algorithm}")

    def _compression_is_worthwhile(self, raw_size: int, compressed_size: int) -> bool:
        saved = raw_size - compressed_size
        if saved <= 0:
            return False
        percent_required = int(raw_size * (self.compression_min_savings_percent / 100.0))
        required = max(percent_required, self.compression_min_savings_bytes)
        # For small chunks, a strict 64 KiB minimum would skip useful text/log
        # compression. Cap the byte threshold to 3 % of small payloads while still
        # keeping the configured percentage rule.
        if raw_size < 2 * 1024 * 1024:
            required = max(percent_required, min(required, int(raw_size * 0.03)))
        return saved >= max(1, required)

    def _probe_compression_candidate(self, data: bytes, algorithm: str) -> bool:
        if len(data) < 128 * 1024:
            return True
        sample_size = min(256 * 1024, max(64 * 1024, len(data) // 8))
        if len(data) <= sample_size * 2:
            sample = data[:sample_size]
        else:
            half = sample_size // 2
            sample = data[:half] + data[-half:]
        try:
            compressed_sample = self._compress_with_algorithm(sample, algorithm, level=1)
        except StorageError:
            return False
        return self._compression_is_worthwhile(len(sample), len(compressed_sample))

    def prepare_chunk_data(
        self,
        data: bytes,
        *,
        file_name: str | None = None,
        file_size: int | None = None,
    ) -> tuple[bytes, str | None]:
        """Return the bytes to store and the compression marker for a raw chunk.

        Compression is adaptive. Already-compressed media/archive formats and
        high-entropy chunks are skipped in ``auto`` mode. A compressed chunk is
        only kept when it saves a meaningful amount of space, which avoids CPU
        spikes on large uploads and small OpenWrt nodes.
        """
        algorithm = self._selected_compression_algorithm()
        if algorithm is None or not data:
            return data, None

        mode = self.compression_mode
        if mode == "auto" and self.compression_skip_incompressible and self._looks_like_precompressed_file(file_name):
            return data, None

        if mode == "auto" and self.compression_skip_incompressible and not self._probe_compression_candidate(data, algorithm):
            return data, None

        compressed = self._compress_with_algorithm(data, algorithm)
        if self._compression_is_worthwhile(len(data), len(compressed)):
            return compressed, algorithm
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
        if compression == "zstd":
            if zstd is None:
                raise StorageError("Compressed chunk uses zstd, but Python package 'zstandard' is not installed")
            try:
                raw = zstd.ZstdDecompressor().decompress(stored_data, max_output_size=int(original_size))
            except Exception as exc:
                raise StorageError("Compressed zstd chunk cannot be decompressed") from exc
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

    def write_chunk(self, data: bytes, index: int = 0, *, file_name: str | None = None, file_size: int | None = None) -> ChunkInfo:
        stored_data, compression = self.prepare_chunk_data(data, file_name=file_name, file_size=file_size)
        return self.write_stored_chunk(
            stored_data,
            original_size=len(data),
            index=index,
            compression=compression,
            validate=False,
        )

    def chunk_file(self, source: BinaryIO, *, file_name: str | None = None, file_size: int | None = None) -> list[ChunkInfo]:
        chunks: list[ChunkInfo] = []
        index = 0
        while True:
            data = source.read(self.chunk_size)
            if not data:
                break
            chunks.append(self.write_chunk(data, index=index, file_name=file_name, file_size=file_size))
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
        if compression == "zstd":
            if zstd is None:
                raise StorageError("Chunk uses zstd compression, but Python package 'zstandard' is not installed")
            return zstd.ZstdDecompressor().decompress(data)
        raise StorageError(f"Unsupported chunk compression {compression}")

    def restore_chunks(
        self,
        chunk_hashes: Iterable[str | dict[str, Any]],
        target: Path,
        *,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> Path:
        target.parent.mkdir(parents=True, exist_ok=True)
        chunks = list(chunk_hashes)
        total_chunks = len(chunks)
        bytes_written = 0
        fd, tmp_name = tempfile.mkstemp(prefix="restore-", suffix=".tmp", dir=self.tmp_dir)
        try:
            with os.fdopen(fd, "wb") as handle:
                for position, chunk in enumerate(chunks, start=1):
                    if isinstance(chunk, dict):
                        digest = str(chunk["hash"])
                        compression = chunk.get("compression")
                        raw_data = self.read_chunk(digest, str(compression) if compression else None)
                    else:
                        digest = str(chunk)
                        raw_data = self.read_chunk(digest)
                    handle.write(raw_data)
                    bytes_written += len(raw_data)
                    if progress_callback is not None:
                        progress_callback(
                            {
                                "phase": "restore_chunk",
                                "current_chunk": position,
                                "total_chunks": total_chunks,
                                "raw_bytes_processed": bytes_written,
                                "digest": digest,
                            }
                        )
                handle.flush()
                os.fsync(handle.fileno())
            Path(tmp_name).replace(target)
        except Exception:
            Path(tmp_name).unlink(missing_ok=True)
            raise
        return target
