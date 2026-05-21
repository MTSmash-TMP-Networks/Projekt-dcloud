"""In-memory progress tracking for interactive uploads.

The browser can report how quickly the multipart request is sent, but the
expensive work starts afterwards: temporary file save, chunking, compression,
peer writes and manifest creation. This small tracker exposes that server-side
work through a polling API so the UI can show a realistic Windows-like copy
status window for large files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import time
from threading import RLock
from typing import Any


@dataclass(slots=True)
class UploadProgress:
    upload_id: str
    known: bool = True
    active: bool = True
    ok: bool | None = None
    phase: str = "waiting"
    status: str = "Upload wartet auf Serververarbeitung…"
    message: str = ""
    file_name: str = ""
    folder_path: str = ""
    percent: float = 0.0
    server_percent: float = 0.0
    total_bytes: int = 0
    raw_bytes_processed: int = 0
    stored_bytes: int = 0
    current_chunk: int = 0
    total_chunks: int = 0
    compressed_chunks: int = 0
    local_chunks: int = 0
    remote_successes: int = 0
    remote_failures: int = 0
    desired_replicas: int = 1
    target_count: int = 0
    current_peer: str = ""
    started_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "uploadId": self.upload_id,
            "known": self.known,
            "active": self.active,
            "ok": self.ok,
            "phase": self.phase,
            "status": self.status,
            "message": self.message,
            "fileName": self.file_name,
            "folderPath": self.folder_path,
            "percent": round(max(0.0, min(100.0, self.percent)), 1),
            "serverPercent": round(max(0.0, min(100.0, self.server_percent)), 1),
            "totalBytes": self.total_bytes,
            "rawBytesProcessed": self.raw_bytes_processed,
            "storedBytes": self.stored_bytes,
            "currentChunk": self.current_chunk,
            "totalChunks": self.total_chunks,
            "compressedChunks": self.compressed_chunks,
            "localChunks": self.local_chunks,
            "remoteSuccesses": self.remote_successes,
            "remoteFailures": self.remote_failures,
            "desiredReplicas": self.desired_replicas,
            "targetCount": self.target_count,
            "currentPeer": self.current_peer,
            "startedAt": self.started_at,
            "updatedAt": self.updated_at,
            "finishedAt": self.finished_at,
            "details": dict(self.details),
        }


class UploadProgressTracker:
    """Thread-safe process-local upload progress registry."""

    def __init__(self, *, ttl_seconds: int = 900, persist_dir: str | Path | None = None) -> None:
        self.ttl_seconds = int(ttl_seconds)
        self._items: dict[str, UploadProgress] = {}
        self._lock = RLock()
        self._persist_dir = Path(persist_dir).expanduser() if persist_dir else None
        if self._persist_dir is not None:
            self._persist_dir.mkdir(parents=True, exist_ok=True)

    def _persist_path(self, upload_id: str) -> Path | None:
        if self._persist_dir is None:
            return None
        safe_id = "".join(char for char in upload_id if char.isalnum() or char in "-_")[:80]
        if not safe_id:
            return None
        return self._persist_dir / f"{safe_id}.json"

    def _save_item(self, item: UploadProgress) -> None:
        path = self._persist_path(item.upload_id)
        if path is None:
            return
        payload = item.to_dict()
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            pass

    def _load_item(self, upload_id: str) -> UploadProgress | None:
        path = self._persist_path(upload_id)
        if path is None or not path.exists():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None
        try:
            item = UploadProgress(
                upload_id=upload_id,
                known=bool(raw.get("known", True)),
                active=bool(raw.get("active", True)),
                ok=raw.get("ok"),
                phase=str(raw.get("phase") or "waiting"),
                status=str(raw.get("status") or "Upload wartet auf Serververarbeitung…"),
                message=str(raw.get("message") or ""),
                file_name=str(raw.get("fileName") or ""),
                folder_path=str(raw.get("folderPath") or ""),
                percent=float(raw.get("percent") or 0.0),
                server_percent=float(raw.get("serverPercent") or 0.0),
                total_bytes=int(raw.get("totalBytes") or 0),
                raw_bytes_processed=int(raw.get("rawBytesProcessed") or 0),
                stored_bytes=int(raw.get("storedBytes") or 0),
                current_chunk=int(raw.get("currentChunk") or 0),
                total_chunks=int(raw.get("totalChunks") or 0),
                compressed_chunks=int(raw.get("compressedChunks") or 0),
                local_chunks=int(raw.get("localChunks") or 0),
                remote_successes=int(raw.get("remoteSuccesses") or 0),
                remote_failures=int(raw.get("remoteFailures") or 0),
                desired_replicas=int(raw.get("desiredReplicas") or 1),
                target_count=int(raw.get("targetCount") or 0),
                current_peer=str(raw.get("currentPeer") or ""),
                started_at=float(raw.get("startedAt") or time.time()),
                updated_at=float(raw.get("updatedAt") or time.time()),
                finished_at=float(raw["finishedAt"]) if raw.get("finishedAt") else None,
                details=dict(raw.get("details") or {}),
            )
            return item
        except (TypeError, ValueError):
            return None

    def get(self, upload_id: str) -> dict[str, Any]:
        self.cleanup()
        with self._lock:
            item = self._items.get(upload_id)
            if item is None:
                loaded = self._load_item(upload_id)
                if loaded is not None:
                    self._items[upload_id] = loaded
                    item = loaded
            if item is None:
                return {
                    "uploadId": upload_id,
                    "known": False,
                    "active": False,
                    "ok": None,
                    "phase": "waiting",
                    "status": "Upload wartet auf Serververarbeitung…",
                    "message": "",
                    "percent": 0,
                    "serverPercent": 0,
                    "totalBytes": 0,
                    "rawBytesProcessed": 0,
                    "storedBytes": 0,
                    "currentChunk": 0,
                    "totalChunks": 0,
                    "compressedChunks": 0,
                    "localChunks": 0,
                    "remoteSuccesses": 0,
                    "remoteFailures": 0,
                    "desiredReplicas": 1,
                    "targetCount": 0,
                    "currentPeer": "",
                    "details": {},
                }
            return item.to_dict()

    def list_recent(self, *, include_finished: bool = True, limit: int = 12) -> list[dict[str, Any]]:
        self.cleanup()
        with self._lock:
            if self._persist_dir is not None:
                for path in sorted(self._persist_dir.glob("*.json")):
                    upload_id = path.stem
                    if upload_id not in self._items:
                        loaded = self._load_item(upload_id)
                        if loaded is not None:
                            self._items[upload_id] = loaded
            items = list(self._items.values())
            items.sort(key=lambda item: float(item.updated_at or item.started_at or 0), reverse=True)
            rows: list[dict[str, Any]] = []
            for item in items:
                if not include_finished and not item.active:
                    continue
                rows.append(item.to_dict())
                if len(rows) >= max(1, int(limit)):
                    break
            return rows

    def start(self, upload_id: str, *, file_name: str = "", folder_path: str = "", total_bytes: int = 0) -> None:
        now = time.time()
        with self._lock:
            self._items[upload_id] = UploadProgress(
                upload_id=upload_id,
                file_name=file_name,
                folder_path=folder_path,
                total_bytes=int(total_bytes or 0),
                started_at=now,
                updated_at=now,
                phase="receiving",
                status="Upload wurde empfangen und wird vorbereitet…",
                percent=35.0,
                server_percent=0.0,
            )
            self._save_item(self._items[upload_id])

    def update(self, upload_id: str, **fields: Any) -> None:
        with self._lock:
            item = self._items.get(upload_id)
            if item is None:
                item = UploadProgress(upload_id=upload_id)
                self._items[upload_id] = item
            details = fields.pop("details", None)
            for key, value in fields.items():
                if not hasattr(item, key):
                    continue
                if key in {"percent", "server_percent"}:
                    value = max(0.0, min(100.0, float(value or 0)))
                elif key in {
                    "total_bytes",
                    "raw_bytes_processed",
                    "stored_bytes",
                    "current_chunk",
                    "total_chunks",
                    "compressed_chunks",
                    "local_chunks",
                    "remote_successes",
                    "remote_failures",
                    "desired_replicas",
                    "target_count",
                }:
                    value = int(value or 0)
                setattr(item, key, value)
            if details:
                item.details.update(details)
            item.updated_at = time.time()
            self._save_item(item)

    def finish(self, upload_id: str, *, ok: bool, message: str = "", details: dict[str, Any] | None = None) -> None:
        now = time.time()
        with self._lock:
            item = self._items.get(upload_id)
            if item is None:
                item = UploadProgress(upload_id=upload_id)
                self._items[upload_id] = item
            item.active = False
            item.ok = bool(ok)
            item.phase = "complete" if ok else "failed"
            item.status = "Abgeschlossen" if ok else "Fehlgeschlagen"
            item.message = message
            item.percent = 100.0 if ok else max(item.percent, 0.0)
            item.server_percent = 100.0 if ok else item.server_percent
            item.finished_at = now
            item.updated_at = now
            if details:
                item.details.update(details)
            self._save_item(item)

    def cleanup(self) -> None:
        cutoff = time.time() - self.ttl_seconds
        with self._lock:
            stale = [
                upload_id
                for upload_id, item in self._items.items()
                if item.updated_at < cutoff and (not item.active or item.started_at < cutoff)
            ]
            for upload_id in stale:
                self._items.pop(upload_id, None)
                path = self._persist_path(upload_id)
                if path is not None:
                    path.unlink(missing_ok=True)
