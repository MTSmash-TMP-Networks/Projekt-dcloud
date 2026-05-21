"""File manifest creation, signing and persistence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import logging
import json
import os
import tempfile
import time
from typing import Any

from .crypto import b64decode, sha256_hex, sign_bytes, verify_signature
from .identity import NodeIdentity
from .storage import ChunkInfo, ChunkStore, StorageError

MANIFEST_VERSION = 1
DEFAULT_FOLDER = "Meine Dateien"
MANIFEST_TRASH_RETENTION = 20
MANIFEST_LOCK_TIMEOUT_SECONDS = 10
MANIFEST_LOCK_POLL_SECONDS = 0.1
MANIFEST_LOCK_STALE_SECONDS = 120
MANIFEST_META_FILES = {"folders.json", "share_revocations.json", "file_deletions.json", "manifest_audit.log"}
LOG = logging.getLogger("dcloud.manifest_store")


@dataclass(frozen=True, slots=True)
class FileManifest:
    manifest_id: str
    file_name: str
    file_size: int
    chunk_size: int
    chunks: list[dict[str, Any]]
    owner_node_id: str
    owner_public_key: str
    created_at: str
    encryption: dict[str, Any]
    signature: str
    placement: dict[str, Any] | None = None
    folder_path: str = DEFAULT_FOLDER
    access: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = {
            "version": MANIFEST_VERSION,
            "manifest_id": self.manifest_id,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "chunk_size": self.chunk_size,
            "chunks": self.chunks,
            "owner_node_id": self.owner_node_id,
            "owner_public_key": self.owner_public_key,
            "created_at": self.created_at,
            "encryption": self.encryption,
            "signature": self.signature,
        }
        if self.placement is not None:
            data["placement"] = self.placement
        data["folder_path"] = self.folder_path
        data["access"] = self.access or {"visibility": "private", "shared_with": []}
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileManifest":
        if data.get("version") != MANIFEST_VERSION:
            raise ValueError("Unsupported manifest version")
        return cls(
            manifest_id=str(data["manifest_id"]),
            file_name=str(data["file_name"]),
            file_size=int(data["file_size"]),
            chunk_size=int(data["chunk_size"]),
            chunks=list(data["chunks"]),
            owner_node_id=str(data["owner_node_id"]),
            owner_public_key=str(data["owner_public_key"]),
            created_at=str(data["created_at"]),
            encryption=dict(data.get("encryption", {"enabled": False})),
            signature=str(data["signature"]),
            placement=dict(data["placement"]) if "placement" in data else None,
            folder_path=sanitize_folder_path(str(data.get("folder_path", DEFAULT_FOLDER))),
            access=dict(data.get("access", {"visibility": "private", "shared_with": []})),
        )


def sanitize_folder_path(value: str) -> str:
    """Normalize a user-facing virtual folder path."""
    cleaned = value.strip().replace("\\", "/")
    parts = [part.strip() for part in cleaned.split("/") if part.strip() and part.strip() not in {".", ".."}]
    return "/".join(parts) if parts else DEFAULT_FOLDER


def canonical_manifest_bytes(data: dict[str, Any]) -> bytes:
    signable = {key: value for key, value in data.items() if key not in {"signature", "manifest_id"}}
    return json.dumps(signable, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ManifestStore:
    def __init__(self, chunk_store: ChunkStore) -> None:
        self.chunk_store = chunk_store
        self.manifests_dir = chunk_store.manifests_dir

    def create_for_file(
        self,
        source: Path,
        identity: NodeIdentity,
        peer_node_ids: list[str] | None = None,
        folder_path: str = DEFAULT_FOLDER,
    ) -> FileManifest:
        file_size = source.stat().st_size
        with source.open("rb") as handle:
            chunk_infos = self.chunk_store.chunk_file(handle)
        return self.create_from_chunks(
            source.name,
            file_size,
            chunk_infos,
            identity,
            peer_node_ids=peer_node_ids,
            folder_path=folder_path,
        )

    def create_from_chunks(
        self,
        file_name: str,
        file_size: int,
        chunk_infos: list[ChunkInfo],
        identity: NodeIdentity,
        peer_node_ids: list[str] | None = None,
        folder_path: str = DEFAULT_FOLDER,
    ) -> FileManifest:
        peer_node_ids = peer_node_ids or []
        storage_targets = [identity.node_id, *peer_node_ids]
        chunk_entries: list[dict[str, Any]] = []
        for c in chunk_infos:
            entry: dict[str, Any] = {
                "index": c.index,
                "hash": c.hash,
                "size": c.size,
                "stored_size": c.stored_size if c.stored_size is not None else c.size,
                "locations": [storage_targets[c.index % len(storage_targets)]] if storage_targets else [identity.node_id],
            }
            if c.compression:
                entry["compression"] = c.compression
            chunk_entries.append(entry)

        return self.create_from_chunk_entries(
            file_name=file_name,
            file_size=file_size,
            chunk_entries=chunk_entries,
            identity=identity,
            folder_path=folder_path,
            placement={
                "strategy": "round_robin_chunks",
                "target_count": len(storage_targets),
                "targets": storage_targets,
                "transfer_status": "local_metadata_only",
            },
        )

    def create_from_chunk_entries(
        self,
        *,
        file_name: str,
        file_size: int,
        chunk_entries: list[dict[str, Any]],
        identity: NodeIdentity,
        folder_path: str = DEFAULT_FOLDER,
        placement: dict[str, Any] | None = None,
        access: dict[str, Any] | None = None,
    ) -> FileManifest:
        now = datetime.now(timezone.utc).isoformat()
        normalized_chunks = sorted((dict(chunk) for chunk in chunk_entries), key=lambda item: int(item["index"]))
        for chunk in normalized_chunks:
            chunk["index"] = int(chunk["index"])
            chunk["hash"] = str(chunk["hash"])
            chunk["size"] = int(chunk["size"])
            chunk["stored_size"] = int(chunk.get("stored_size", chunk["size"]))
            locations = [str(node_id) for node_id in chunk.get("locations", []) if str(node_id)]
            chunk["locations"] = list(dict.fromkeys(locations)) or [identity.node_id]
            if chunk.get("compression") in {None, ""}:
                chunk.pop("compression", None)

        unique_targets = list(dict.fromkeys(
            str(location)
            for chunk in normalized_chunks
            for location in chunk.get("locations", [])
            if str(location)
        ))
        base: dict[str, Any] = {
            "version": MANIFEST_VERSION,
            "file_name": file_name,
            "file_size": file_size,
            "chunk_size": self.chunk_store.chunk_size,
            "chunks": normalized_chunks,
            "owner_node_id": identity.node_id,
            "owner_public_key": identity.public_key_b64,
            "created_at": now,
            "encryption": {"enabled": False, "algorithm": None},
            "folder_path": sanitize_folder_path(folder_path),
            "access": access or {"visibility": "private", "shared_with": []},
            "placement": placement or {
                "strategy": "distributed_round_robin_chunks",
                "target_count": len(unique_targets),
                "targets": unique_targets,
                "transfer_status": "local_only" if unique_targets == [identity.node_id] else "stored_on_peers",
            },
        }
        signature = sign_bytes(identity.private_key, canonical_manifest_bytes(base))
        manifest_id = sha256_hex(canonical_manifest_bytes({**base, "signature": signature}))
        manifest = FileManifest.from_dict({**base, "manifest_id": manifest_id, "signature": signature})
        self.save(manifest)
        return manifest

    def save(self, manifest: FileManifest) -> Path:
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        data = json.dumps(manifest.to_dict(), sort_keys=True, indent=2).encode("utf-8")
        self.chunk_store.ensure_capacity(len(data))
        self._acquire_manifest_lock()
        fd, tmp_name = tempfile.mkstemp(prefix="manifest-", suffix=".tmp", dir=self.chunk_store.tmp_dir)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            target = self.path_for(manifest.manifest_id)
            self._backup_existing_file(target)
            Path(tmp_name).replace(target)
            self._append_audit_event("write", {"manifest_id": manifest.manifest_id, "target": str(target)})
            return target
        except Exception as exc:
            self._append_audit_event("write_error", {"manifest_id": manifest.manifest_id, "error": str(exc)})
            Path(tmp_name).unlink(missing_ok=True)
            raise
        finally:
            self._release_manifest_lock()

    def path_for(self, manifest_id: str) -> Path:
        return self.manifests_dir / f"{manifest_id}.json"

    def list_manifests(self) -> list[FileManifest]:
        manifests: list[FileManifest] = []
        if not self.manifests_dir.exists():
            return manifests
        for path in sorted(self.manifests_dir.glob("*.json")):
            if path.name in MANIFEST_META_FILES:
                continue
            try:
                manifests.append(self.load(path.stem))
            except Exception:
                continue
        return manifests

    def list_visible_for_node(self, node_id: str) -> list[FileManifest]:
        """Return manifests visible to a node: own files plus explicit shares."""
        return [manifest for manifest in self.list_manifests() if self.may_access(manifest, node_id)]

    def list_folders_for_node(self, node_id: str) -> list[str]:
        folders = {DEFAULT_FOLDER}
        for manifest in self.list_visible_for_node(node_id):
            folders.add(manifest.folder_path)
        folders.update(self._load_saved_folders(node_id))
        return sorted(folders, key=str.lower)

    def create_folder(self, folder_path: str, owner_node_id: str) -> str:
        folder_path = sanitize_folder_path(folder_path)
        folders = set(self._load_saved_folders(owner_node_id))
        parts = [part for part in folder_path.split("/") if part]
        current = ""
        for part in parts:
            current = f"{current}/{part}" if current else part
            folders.add(current)
        self._save_folders(owner_node_id, sorted(folders, key=str.lower))
        return folder_path

    def delete_folder(self, folder_path: str, owner_node_id: str, *, delete_files: bool = True) -> dict[str, int | str]:
        """Delete a user-created virtual folder and optionally owned files below it.

        Shared manifests that belong to other nodes are intentionally left untouched.
        If such files are still visible to the user, the virtual folder may reappear
        because it still contains shared content.
        """
        folder_path = sanitize_folder_path(folder_path)
        if folder_path == DEFAULT_FOLDER:
            raise StorageError("Der Standardordner kann nicht gelöscht werden")

        def is_in_folder(candidate: str) -> bool:
            candidate = sanitize_folder_path(candidate)
            return candidate == folder_path or candidate.startswith(f"{folder_path}/")

        owned_manifests = [
            manifest
            for manifest in self.list_manifests()
            if manifest.owner_node_id == owner_node_id and is_in_folder(manifest.folder_path)
        ]
        if delete_files:
            for manifest in owned_manifests:
                self.delete(manifest.manifest_id)

        saved_folders = set(self._load_saved_folders(owner_node_id))
        remaining_folders = {folder for folder in saved_folders if not is_in_folder(folder)}
        removed_folders = len(saved_folders) - len(remaining_folders)
        self._save_folders(owner_node_id, sorted(remaining_folders, key=str.lower))

        return {
            "folder": folder_path,
            "deleted_files": len(owned_manifests),
            "deleted_folders": removed_folders,
        }

    def is_shared(self, manifest: FileManifest) -> bool:
        visibility = (manifest.access or {}).get("visibility")
        return visibility in {"shared", "public"}

    def may_access(self, manifest: FileManifest, node_id: str) -> bool:
        current_node_id = str(node_id)
        if str(manifest.owner_node_id) == current_node_id:
            return True
        access = manifest.access or {}
        visibility = str(access.get("visibility") or "").lower()
        if visibility == "public":
            return True
        shared_with = {str(item) for item in access.get("shared_with", [])}
        return visibility == "shared" and ("*" in shared_with or current_node_id in shared_with)

    def _resign_manifest(
        self,
        manifest: FileManifest,
        identity: NodeIdentity,
        updates: dict[str, Any],
    ) -> FileManifest:
        if manifest.owner_node_id != identity.node_id:
            raise StorageError("Only the owner can change this manifest")
        data = manifest.to_dict()
        old_path = self.path_for(manifest.manifest_id)
        data.update(updates)
        data.pop("signature", None)
        data.pop("manifest_id", None)
        signature = sign_bytes(identity.private_key, canonical_manifest_bytes(data))
        new_manifest_id = sha256_hex(canonical_manifest_bytes({**data, "signature": signature}))
        updated = FileManifest.from_dict({**data, "manifest_id": new_manifest_id, "signature": signature})
        self.save(updated)
        if old_path != self.path_for(updated.manifest_id):
            self._move_to_trash(old_path)
            self._append_audit_event("resign_old_manifest_retired", {"path": str(old_path), "new_manifest_id": updated.manifest_id})
        return updated

    def set_shared(
        self,
        manifest_id: str,
        shared: bool,
        identity: NodeIdentity,
        shared_with: list[str] | None = None,
    ) -> FileManifest:
        manifest = self.load(manifest_id)
        targets = list(dict.fromkeys(str(item) for item in (shared_with or ["*"]) if str(item)))
        access = {"visibility": "shared" if shared else "private", "shared_with": targets if shared else []}
        return self._resign_manifest(manifest, identity, {"access": access})

    def move_to_folder(self, manifest_id: str, folder_path: str, identity: NodeIdentity) -> FileManifest:
        manifest = self.load(manifest_id)
        destination = sanitize_folder_path(folder_path)
        if destination == sanitize_folder_path(manifest.folder_path):
            return manifest
        self.create_folder(destination, identity.node_id)
        return self._resign_manifest(manifest, identity, {"folder_path": destination})

    def update_placement(
        self,
        manifest_id: str,
        identity: NodeIdentity,
        *,
        chunks: list[dict[str, Any]] | None = None,
        placement: dict[str, Any] | None = None,
    ) -> FileManifest:
        manifest = self.load(manifest_id)
        updates: dict[str, Any] = {}
        if chunks is not None:
            updates["chunks"] = chunks
        if placement is not None:
            updates["placement"] = placement
        return self._resign_manifest(manifest, identity, updates)

    def save_imported(self, manifest: FileManifest) -> Path:
        if not self.verify(manifest):
            raise StorageError(f"Manifest signature verification failed for {manifest.manifest_id}")
        return self.save(manifest)

    @property
    def folders_path(self) -> Path:
        return self.manifests_dir / "folders.json"

    def _load_saved_folders(self, owner_node_id: str) -> list[str]:
        if not self.folders_path.exists():
            return []
        try:
            data = json.loads(self.folders_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        return [sanitize_folder_path(folder) for folder in data.get(owner_node_id, [])]

    def _save_folders(self, owner_node_id: str, folders: list[str]) -> None:
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        data: dict[str, list[str]] = {}
        if self.folders_path.exists():
            try:
                loaded = json.loads(self.folders_path.read_text(encoding="utf-8"))
                data = {str(key): list(value) for key, value in loaded.items()}
            except (json.JSONDecodeError, TypeError):
                data = {}
        data[owner_node_id] = folders
        self._write_json_atomically(self.folders_path, data, "save_folders")

    @property
    def share_revocations_path(self) -> Path:
        return self.manifests_dir / "share_revocations.json"

    def _load_share_revocations(self) -> list[dict[str, Any]]:
        if not self.share_revocations_path.exists():
            return []
        try:
            raw = json.loads(self.share_revocations_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        if not isinstance(raw, list):
            return []
        result: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            manifest_id = str(item.get("manifest_id", ""))
            owner_node_id = str(item.get("owner_node_id", ""))
            if not manifest_id or not owner_node_id:
                continue
            cleaned = dict(item)
            cleaned["manifest_id"] = manifest_id
            cleaned["owner_node_id"] = owner_node_id
            cleaned["target_node_ids"] = list(dict.fromkeys(str(value) for value in item.get("target_node_ids", []) if str(value)))
            cleaned["delivered_node_ids"] = list(dict.fromkeys(str(value) for value in item.get("delivered_node_ids", []) if str(value)))
            result.append(cleaned)
        return result

    def _save_share_revocations(self, revocations: list[dict[str, Any]]) -> None:
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        self._write_json_atomically(self.share_revocations_path, revocations, "save_share_revocations")

    def add_share_revocation(self, revocation: dict[str, Any], target_node_ids: list[str] | None = None) -> None:
        """Persist a share revocation/tombstone and optional delivery targets."""
        target_node_ids = target_node_ids or []
        clean_targets = list(dict.fromkeys(str(node_id) for node_id in target_node_ids if str(node_id)))
        manifest_id = str(revocation.get("manifest_id", ""))
        owner_node_id = str(revocation.get("owner_node_id", ""))
        if not manifest_id or not owner_node_id:
            raise StorageError("Revocation payload is incomplete")

        records = self._load_share_revocations()
        for record in records:
            if record.get("manifest_id") == manifest_id and record.get("owner_node_id") == owner_node_id:
                merged_targets = list(dict.fromkeys([*record.get("target_node_ids", []), *clean_targets]))
                delivered = list(dict.fromkeys(str(node_id) for node_id in record.get("delivered_node_ids", []) if str(node_id)))
                record.update(revocation)
                record["target_node_ids"] = merged_targets
                record["delivered_node_ids"] = delivered
                self._save_share_revocations(records)
                return

        record = dict(revocation)
        record["target_node_ids"] = clean_targets
        record["delivered_node_ids"] = []
        records.append(record)
        self._save_share_revocations(records)

    def clear_share_revocation(self, manifest_id: str, owner_node_id: str) -> bool:
        """Remove stored revocation tombstones for a manifest when it is shared again."""
        records = self._load_share_revocations()
        kept = [
            record
            for record in records
            if not (record.get("manifest_id") == str(manifest_id) and record.get("owner_node_id") == str(owner_node_id))
        ]
        if len(kept) == len(records):
            return False
        self._save_share_revocations(kept)
        return True

    def list_pending_share_revocations(self, owner_node_id: str) -> list[dict[str, Any]]:
        """Return owner-created revocations that still need peer delivery."""
        pending: list[dict[str, Any]] = []
        for record in self._load_share_revocations():
            if record.get("owner_node_id") != owner_node_id:
                continue
            targets = set(record.get("target_node_ids", []))
            delivered = set(record.get("delivered_node_ids", []))
            if "*" in targets:
                if not delivered:
                    pending.append(record)
                continue
            if targets - delivered:
                pending.append(record)
        return pending

    def mark_share_revocation_delivered(self, manifest_id: str, owner_node_id: str, target_node_id: str) -> None:
        records = self._load_share_revocations()
        changed = False
        for record in records:
            if record.get("manifest_id") == manifest_id and record.get("owner_node_id") == owner_node_id:
                delivered = list(dict.fromkeys([*record.get("delivered_node_ids", []), str(target_node_id)]))
                record["delivered_node_ids"] = delivered
                changed = True
        if changed:
            self._save_share_revocations(records)

    def is_share_revoked(self, manifest_id: str, owner_node_id: str) -> bool:
        return any(
            record.get("manifest_id") == str(manifest_id) and record.get("owner_node_id") == str(owner_node_id)
            for record in self._load_share_revocations()
        )

    @property
    def file_deletions_path(self) -> Path:
        return self.manifests_dir / "file_deletions.json"

    def _load_file_deletions(self) -> list[dict[str, Any]]:
        if not self.file_deletions_path.exists():
            return []
        try:
            raw = json.loads(self.file_deletions_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        if not isinstance(raw, list):
            return []
        result: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            manifest_id = str(item.get("manifest_id", ""))
            owner_node_id = str(item.get("owner_node_id", ""))
            if not manifest_id or not owner_node_id:
                continue
            cleaned = dict(item)
            cleaned["manifest_id"] = manifest_id
            cleaned["owner_node_id"] = owner_node_id
            cleaned["target_node_ids"] = list(dict.fromkeys(str(value) for value in item.get("target_node_ids", []) if str(value)))
            cleaned["delivered_node_ids"] = list(dict.fromkeys(str(value) for value in item.get("delivered_node_ids", []) if str(value)))
            result.append(cleaned)
        return result

    def _save_file_deletions(self, deletions: list[dict[str, Any]]) -> None:
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        self._write_json_atomically(self.file_deletions_path, deletions, "save_file_deletions")

    def add_file_deletion(self, deletion: dict[str, Any], target_node_ids: list[str] | None = None) -> None:
        """Persist a signed file-delete tombstone and optional delivery targets."""
        target_node_ids = target_node_ids or []
        clean_targets = list(dict.fromkeys(str(node_id) for node_id in target_node_ids if str(node_id)))
        manifest_id = str(deletion.get("manifest_id", ""))
        owner_node_id = str(deletion.get("owner_node_id", ""))
        if not manifest_id or not owner_node_id:
            raise StorageError("File deletion payload is incomplete")

        records = self._load_file_deletions()
        for record in records:
            if record.get("manifest_id") == manifest_id and record.get("owner_node_id") == owner_node_id:
                merged_targets = list(dict.fromkeys([*record.get("target_node_ids", []), *clean_targets]))
                delivered = list(dict.fromkeys(str(node_id) for node_id in record.get("delivered_node_ids", []) if str(node_id)))
                record.update(deletion)
                record["target_node_ids"] = merged_targets
                record["delivered_node_ids"] = delivered
                self._save_file_deletions(records)
                return

        record = dict(deletion)
        record["target_node_ids"] = clean_targets
        record["delivered_node_ids"] = []
        records.append(record)
        self._save_file_deletions(records)

    def list_pending_file_deletions(self, owner_node_id: str) -> list[dict[str, Any]]:
        """Return owner-created file deletions that still need peer delivery."""
        pending: list[dict[str, Any]] = []
        for record in self._load_file_deletions():
            if record.get("owner_node_id") != owner_node_id:
                continue
            targets = set(record.get("target_node_ids", []))
            delivered = set(record.get("delivered_node_ids", []))
            if "*" in targets:
                if not delivered:
                    pending.append(record)
                continue
            if targets - delivered:
                pending.append(record)
        return pending

    def mark_file_deletion_delivered(self, manifest_id: str, owner_node_id: str, target_node_id: str) -> None:
        records = self._load_file_deletions()
        changed = False
        for record in records:
            if record.get("manifest_id") == manifest_id and record.get("owner_node_id") == owner_node_id:
                delivered = list(dict.fromkeys([*record.get("delivered_node_ids", []), str(target_node_id)]))
                record["delivered_node_ids"] = delivered
                changed = True
        if changed:
            self._save_file_deletions(records)

    def is_file_deleted(self, manifest_id: str, owner_node_id: str) -> bool:
        return any(
            record.get("manifest_id") == str(manifest_id) and record.get("owner_node_id") == str(owner_node_id)
            for record in self._load_file_deletions()
        )

    def delete_chunks_if_unreferenced(self, chunk_hashes: list[str]) -> int:
        """Remove local chunk files only when no remaining manifest references them."""
        still_referenced = {
            str(chunk["hash"])
            for remaining in self.list_manifests()
            for chunk in remaining.chunks
        }
        removed = 0
        for digest in list(dict.fromkeys(str(value) for value in chunk_hashes if str(value))):
            if digest in still_referenced:
                continue
            path = self.chunk_store.chunk_path(digest)
            if path.exists():
                path.unlink(missing_ok=True)
                removed += 1
                try:
                    path.parent.rmdir()
                except OSError:
                    pass
        return removed

    def load(self, manifest_id: str) -> FileManifest:
        path = self.path_for(manifest_id)
        if not path.exists():
            if self._restore_from_backup(path):
                self._append_audit_event("restore_from_backup", {"manifest_id": manifest_id, "path": str(path)})
            elif self._restore_from_trash(path):
                self._append_audit_event("restore_from_trash", {"manifest_id": manifest_id, "path": str(path)})
            else:
                self._append_audit_event("read_missing", {"manifest_id": manifest_id})
                raise StorageError(f"Manifest {manifest_id} not found")
        raw_data = json.loads(path.read_text(encoding="utf-8"))
        if not self.verify_raw(raw_data):
            self._append_audit_event("signature_invalid", {"manifest_id": manifest_id, "path": str(path)})
            self._quarantine_invalid_manifest(path, manifest_id)
            raise StorageError(f"Manifest signature verification failed for {manifest_id}")
        manifest = FileManifest.from_dict(raw_data)
        return manifest

    def verify(self, manifest: FileManifest) -> bool:
        return verify_signature(
            b64decode(manifest.owner_public_key),
            canonical_manifest_bytes(manifest.to_dict()),
            manifest.signature,
        )

    def verify_raw(self, raw_manifest: dict[str, Any]) -> bool:
        """Verify signature against the persisted JSON payload without normalization side effects."""
        signature = str(raw_manifest.get("signature", ""))
        public_key = raw_manifest.get("owner_public_key")
        if not signature or not isinstance(public_key, str):
            return False
        return verify_signature(
            b64decode(public_key),
            canonical_manifest_bytes(raw_manifest),
            signature,
        )

    def restore(self, manifest_id: str, target: Path | None = None) -> Path:
        manifest = self.load(manifest_id)
        output = target or (self.chunk_store.downloads_dir / manifest.file_name)
        chunks = sorted(manifest.chunks, key=lambda item: int(item["index"]))
        return self.chunk_store.restore_chunks(chunks, output)

    def delete(self, manifest_id: str, *, delete_unreferenced_chunks: bool = True) -> None:
        manifest = self.load(manifest_id)
        manifest_path = self.path_for(manifest_id)
        self._acquire_manifest_lock()
        try:
            if manifest_path.exists():
                self._move_to_trash(manifest_path)
                self._append_audit_event("delete", {"manifest_id": manifest_id, "path": str(manifest_path)})
            else:
                self._append_audit_event("delete_missing", {"manifest_id": manifest_id, "path": str(manifest_path)})
        finally:
            self._release_manifest_lock()

        if not delete_unreferenced_chunks:
            return

        self.delete_chunks_if_unreferenced([str(chunk["hash"]) for chunk in manifest.chunks])

    @property
    def trash_dir(self) -> Path:
        return self.manifests_dir / ".trash"

    @property
    def lock_file(self) -> Path:
        return self.manifests_dir / ".manifest.lock"

    @property
    def audit_log_path(self) -> Path:
        return self.manifests_dir / "manifest_audit.log"

    def _write_json_atomically(self, target: Path, payload: Any, event_name: str) -> None:
        self._acquire_manifest_lock()
        fd, tmp_name = tempfile.mkstemp(prefix=f"{target.stem}-", suffix=".tmp", dir=self.chunk_store.tmp_dir)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(json.dumps(payload, sort_keys=True, indent=2).encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            self._backup_existing_file(target)
            Path(tmp_name).replace(target)
            self._append_audit_event(event_name, {"target": str(target)})
        finally:
            Path(tmp_name).unlink(missing_ok=True)
            self._release_manifest_lock()

    def _backup_existing_file(self, path: Path) -> None:
        if path.exists():
            backup_path = path.with_suffix(f"{path.suffix}.bak")
            path.replace(backup_path)
            self._append_audit_event("backup", {"source": str(path), "backup": str(backup_path)})

    def _quarantine_invalid_manifest(self, path: Path, manifest_id: str) -> None:
        """Move invalid manifests out of the active directory to avoid endless re-validation loops."""
        if not path.exists():
            return
        self._acquire_manifest_lock()
        try:
            invalid_dir = self.manifests_dir / ".invalid"
            invalid_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
            target = invalid_dir / f"{manifest_id}-{timestamp}.json"
            suffix = 1
            while target.exists():
                target = invalid_dir / f"{manifest_id}-{timestamp}-{suffix}.json"
                suffix += 1
            path.replace(target)
            self._append_audit_event(
                "signature_invalid_quarantined",
                {"manifest_id": manifest_id, "source": str(path), "target": str(target)},
            )
        except Exception as exc:
            LOG.warning("Ungültiges Manifest konnte nicht quarantined werden: %s", path, exc_info=True)
            self._append_audit_event(
                "signature_invalid_quarantine_failed",
                {"manifest_id": manifest_id, "path": str(path), "error": str(exc)},
            )
        finally:
            self._release_manifest_lock()

    def _restore_from_backup(self, path: Path) -> bool:
        backup_path = path.with_suffix(f"{path.suffix}.bak")
        if not backup_path.exists():
            return False
        backup_path.replace(path)
        return True

    def _move_to_trash(self, path: Path) -> None:
        if not path.exists():
            return
        self.trash_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        target = self.trash_dir / f"{ts}-{path.name}"
        path.replace(target)
        self._purge_old_trash()

    def _restore_from_trash(self, path: Path) -> bool:
        if not self.trash_dir.exists():
            return False
        candidates = sorted(self.trash_dir.glob(f"*-{path.name}"), reverse=True)
        if not candidates:
            return False
        candidates[0].replace(path)
        return True

    def _purge_old_trash(self) -> None:
        entries = sorted(self.trash_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
        for stale in entries[MANIFEST_TRASH_RETENTION:]:
            stale.unlink(missing_ok=True)

    def _acquire_manifest_lock(self) -> None:
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        for _ in range(MANIFEST_LOCK_TIMEOUT_SECONDS * 10):
            try:
                fd = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(str(os.getpid()))
                return
            except FileExistsError:
                try:
                    age = time.time() - self.lock_file.stat().st_mtime
                    if age > MANIFEST_LOCK_STALE_SECONDS:
                        self._append_audit_event("lock_stale_removed", {"path": str(self.lock_file), "age_seconds": int(age)})
                        self.lock_file.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                time.sleep(MANIFEST_LOCK_POLL_SECONDS)
        raise StorageError("Manifest lock could not be acquired")

    def _release_manifest_lock(self) -> None:
        self.lock_file.unlink(missing_ok=True)

    def _append_audit_event(self, event: str, payload: dict[str, Any]) -> None:
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        row = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "payload": payload,
        }
        with self.audit_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
        LOG.info("Manifest event %s: %s", event, payload)

    def run_manifest_consistency_check(self) -> dict[str, int]:
        repaired_backup = 0
        repaired_trash = 0
        invalid = 0
        for path in sorted(self.manifests_dir.glob("*.json")):
            if path.name in MANIFEST_META_FILES:
                continue
            try:
                manifest = FileManifest.from_dict(json.loads(path.read_text(encoding="utf-8")))
                if not self.verify(manifest):
                    invalid += 1
                    self._append_audit_event("consistency_invalid", {"path": str(path)})
            except Exception:
                if self._restore_from_backup(path):
                    repaired_backup += 1
                elif self._restore_from_trash(path):
                    repaired_trash += 1
                else:
                    invalid += 1
        summary = {"repaired_backup": repaired_backup, "repaired_trash": repaired_trash, "invalid": invalid}
        self._append_audit_event("consistency_run", summary)
        return summary
