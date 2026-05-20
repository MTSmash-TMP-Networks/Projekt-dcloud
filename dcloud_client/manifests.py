"""File manifest creation, signing and persistence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3
from typing import Any

from .crypto import b64decode, sha256_hex, sign_bytes, verify_signature
from .identity import NodeIdentity
from .storage import ChunkInfo, ChunkStore, StorageError

MANIFEST_VERSION = 1
DEFAULT_FOLDER = "Meine Dateien"


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
        self.db_path = self.manifests_dir / "manifest_store.db"
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        self.manifests_dir.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS manifests (manifest_id TEXT PRIMARY KEY, data TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS manifest_aliases (old_id TEXT PRIMARY KEY, new_id TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS folders (owner_node_id TEXT NOT NULL, folder_path TEXT NOT NULL, PRIMARY KEY(owner_node_id, folder_path))")
            conn.execute("CREATE TABLE IF NOT EXISTS share_revocations (manifest_id TEXT NOT NULL, owner_node_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(manifest_id, owner_node_id))")
            conn.execute("CREATE TABLE IF NOT EXISTS file_deletions (manifest_id TEXT NOT NULL, owner_node_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(manifest_id, owner_node_id))")

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
        normalized_chunks = self._normalize_chunk_entries(chunk_entries, identity)

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
                "strategy": "distributed_direct_first_chunks",
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

    def update_from_chunk_entries(
        self,
        manifest_id: str,
        *,
        file_name: str,
        file_size: int,
        chunk_entries: list[dict[str, Any]],
        identity: NodeIdentity,
        folder_path: str = DEFAULT_FOLDER,
        placement: dict[str, Any] | None = None,
    ) -> FileManifest:
        """Update an existing owned manifest in-place while preserving manifest_id."""
        manifest = self.load(manifest_id)
        normalized_chunks = self._normalize_chunk_entries(chunk_entries, identity)
        unique_targets = list(dict.fromkeys(
            str(location)
            for chunk in normalized_chunks
            for location in chunk.get("locations", [])
            if str(location)
        ))
        updates: dict[str, Any] = {
            "file_name": file_name,
            "file_size": int(file_size),
            "chunks": normalized_chunks,
            "folder_path": sanitize_folder_path(folder_path),
            "placement": placement or {
                "strategy": "distributed_direct_first_chunks",
                "target_count": len(unique_targets),
                "targets": unique_targets,
                "transfer_status": "local_only" if unique_targets == [identity.node_id] else "stored_on_peers",
            },
        }
        previous_chunk_hashes = [str(chunk["hash"]) for chunk in manifest.chunks]
        updated_manifest = self._resign_manifest(manifest, identity, updates, rekey=False)
        self.delete_chunks_if_unreferenced(previous_chunk_hashes)
        return updated_manifest

    def _normalize_chunk_entries(self, chunk_entries: list[dict[str, Any]], identity: NodeIdentity) -> list[dict[str, Any]]:
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
        return normalized_chunks

    def save(self, manifest: FileManifest) -> Path:
        data = json.dumps(manifest.to_dict(), sort_keys=True)
        self.chunk_store.ensure_capacity(len(data.encode("utf-8")))
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO manifests (manifest_id, data) VALUES (?, ?)", (manifest.manifest_id, data))
        return self.path_for(manifest.manifest_id)

    def path_for(self, manifest_id: str) -> Path:
        return self.manifests_dir / f"{manifest_id}.json"

    def list_manifests(self) -> list[FileManifest]:
        manifests: list[FileManifest] = []
        with self._connect() as conn:
            rows = conn.execute("SELECT manifest_id FROM manifests ORDER BY manifest_id").fetchall()
        for row in rows:
            try:
                manifests.append(self.load(str(row["manifest_id"])))
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
        if manifest.owner_node_id == node_id:
            return True
        access = manifest.access or {}
        visibility = access.get("visibility")
        shared_with = {str(item) for item in access.get("shared_with", [])}
        return visibility in {"shared", "public"} and ("*" in shared_with or node_id in shared_with)

    def _resign_manifest(
        self,
        manifest: FileManifest,
        identity: NodeIdentity,
        updates: dict[str, Any],
        *,
        rekey: bool = False,
    ) -> FileManifest:
        """Re-sign an owned manifest after metadata changes.

        By default the existing manifest id is preserved. For access/share changes,
        pass ``rekey=True`` so the changed manifest receives a fresh id. That keeps
        old share revocation tombstones from invalidating a newly shared manifest
        with the same id on remote peers.
        """
        if manifest.owner_node_id != identity.node_id:
            raise StorageError("Only the owner can change this manifest")

        old_manifest_id = manifest.manifest_id
        data = manifest.to_dict()
        data.update(updates)
        data.pop("signature", None)

        if rekey:
            data.pop("manifest_id", None)
            signature = sign_bytes(identity.private_key, canonical_manifest_bytes(data))
            new_manifest_id = sha256_hex(canonical_manifest_bytes({**data, "signature": signature}))
            updated = FileManifest.from_dict({
                **data,
                "manifest_id": new_manifest_id,
                "signature": signature,
            })
            self.save(updated)

            if new_manifest_id != old_manifest_id:
                with self._connect() as conn:
                    conn.execute("DELETE FROM manifests WHERE manifest_id = ?", (old_manifest_id,))
                self._record_manifest_alias(old_manifest_id, new_manifest_id)

            return updated

        data["manifest_id"] = old_manifest_id
        signature = sign_bytes(identity.private_key, canonical_manifest_bytes(data))
        updated = FileManifest.from_dict({**data, "signature": signature})
        self.save(updated)
        return updated

    def _load_manifest_aliases(self) -> dict[str, str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT old_id, new_id FROM manifest_aliases").fetchall()
        return {str(row["old_id"]): str(row["new_id"]) for row in rows if str(row["old_id"]) != str(row["new_id"])}

    def _save_manifest_aliases(self, aliases: dict[str, str]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM manifest_aliases")
            conn.executemany("INSERT INTO manifest_aliases (old_id, new_id) VALUES (?, ?)", aliases.items())

    def _record_manifest_alias(self, old_manifest_id: str, new_manifest_id: str) -> None:
        old_manifest_id = str(old_manifest_id)
        new_manifest_id = str(new_manifest_id)
        if not old_manifest_id or not new_manifest_id or old_manifest_id == new_manifest_id:
            return
        aliases = self._load_manifest_aliases()
        resolved_new = new_manifest_id
        aliases[old_manifest_id] = resolved_new
        for alias, current in list(aliases.items()):
            if current == old_manifest_id:
                aliases[alias] = resolved_new
        aliases = {old_id: new_id for old_id, new_id in aliases.items() if old_id != new_id}
        self._save_manifest_aliases(aliases)

    def resolve_manifest_id(self, manifest_id: str, *, aliases: dict[str, str] | None = None) -> str:
        manifest_id = str(manifest_id)
        aliases = aliases if aliases is not None else self._load_manifest_aliases()
        seen: set[str] = set()
        current = manifest_id
        while current in aliases and current not in seen:
            seen.add(current)
            current = aliases[current]
        return current

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

        current_access = manifest.access or {"visibility": "private", "shared_with": []}
        current_visibility = str(current_access.get("visibility", "private"))
        current_targets = list(dict.fromkeys(str(item) for item in current_access.get("shared_with", []) if str(item)))
        normalized_current = {
            "visibility": "shared" if current_visibility in {"shared", "public"} else "private",
            "shared_with": current_targets if current_visibility in {"shared", "public"} else [],
        }

        if normalized_current == access:
            # No access change: avoid creating a new manifest id/signature revision.
            return manifest

        return self._resign_manifest(manifest, identity, {"access": access}, rekey=True)

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

    def _load_saved_folders(self, owner_node_id: str) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT folder_path FROM folders WHERE owner_node_id = ? ORDER BY lower(folder_path)", (owner_node_id,)).fetchall()
        return [sanitize_folder_path(str(row["folder_path"])) for row in rows]

    def _save_folders(self, owner_node_id: str, folders: list[str]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM folders WHERE owner_node_id = ?", (owner_node_id,))
            conn.executemany("INSERT OR IGNORE INTO folders (owner_node_id, folder_path) VALUES (?, ?)", [(owner_node_id, sanitize_folder_path(folder)) for folder in folders])

    def _load_share_revocations(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT data FROM share_revocations").fetchall()
        raw = []
        for row in rows:
            try:
                raw.append(json.loads(str(row["data"])))
            except json.JSONDecodeError:
                continue
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
        with self._connect() as conn:
            conn.execute("DELETE FROM share_revocations")
            conn.executemany("INSERT OR REPLACE INTO share_revocations (manifest_id, owner_node_id, data) VALUES (?, ?, ?)", [(str(item.get("manifest_id", "")), str(item.get("owner_node_id", "")), json.dumps(item, sort_keys=True)) for item in revocations])

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

    def list_pending_share_revocations(self, owner_node_id: str) -> list[dict[str, Any]]:
        """Return owner-created revocations that still need peer delivery."""
        pending: list[dict[str, Any]] = []
        for record in self._load_share_revocations():
            if record.get("owner_node_id") != owner_node_id:
                continue
            targets = set(record.get("target_node_ids", []))
            delivered = set(record.get("delivered_node_ids", []))
            if "*" in targets or targets - delivered:
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

    def clear_share_revocation(self, manifest_id: str, owner_node_id: str) -> bool:
        """Remove a previously persisted share revocation tombstone.

        This is needed when an owner intentionally shares the exact same
        manifest again. Without clearing the old tombstone first, receivers
        reject the fresh manifest as already revoked and it disappears again
        after relay delivery.
        """
        target_manifest_id = str(manifest_id)
        target_owner_node_id = str(owner_node_id)
        records = self._load_share_revocations()
        filtered = [
            record
            for record in records
            if not (
                record.get("manifest_id") == target_manifest_id
                and record.get("owner_node_id") == target_owner_node_id
            )
        ]
        if len(filtered) == len(records):
            return False
        self._save_share_revocations(filtered)
        return True

    def _load_file_deletions(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT data FROM file_deletions").fetchall()
        raw = []
        for row in rows:
            try:
                raw.append(json.loads(str(row["data"])))
            except json.JSONDecodeError:
                continue
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
        with self._connect() as conn:
            conn.execute("DELETE FROM file_deletions")
            conn.executemany("INSERT OR REPLACE INTO file_deletions (manifest_id, owner_node_id, data) VALUES (?, ?, ?)", [(str(item.get("manifest_id", "")), str(item.get("owner_node_id", "")), json.dumps(item, sort_keys=True)) for item in deletions])

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
            if "*" in targets or targets - delivered:
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
        resolved_manifest_id = self.resolve_manifest_id(manifest_id)
        with self._connect() as conn:
            row = conn.execute("SELECT data FROM manifests WHERE manifest_id = ?", (resolved_manifest_id,)).fetchone()
        if row is None:
            raise StorageError(f"Manifest {manifest_id} not found")
        manifest = FileManifest.from_dict(json.loads(str(row["data"])))
        if not self.verify(manifest):
            raise StorageError(f"Manifest signature verification failed for {resolved_manifest_id}")
        return manifest

    def verify(self, manifest: FileManifest) -> bool:
        return verify_signature(
            b64decode(manifest.owner_public_key),
            canonical_manifest_bytes(manifest.to_dict()),
            manifest.signature,
        )

    def restore(self, manifest_id: str, target: Path | None = None) -> Path:
        manifest = self.load(manifest_id)
        output = target or (self.chunk_store.downloads_dir / manifest.file_name)
        chunks = sorted(manifest.chunks, key=lambda item: int(item["index"]))
        return self.chunk_store.restore_chunks(chunks, output)

    def delete(self, manifest_id: str, *, delete_unreferenced_chunks: bool = True) -> None:
        manifest = self.load(manifest_id)
        with self._connect() as conn:
            conn.execute("DELETE FROM manifests WHERE manifest_id = ?", (manifest.manifest_id,))

        if not delete_unreferenced_chunks:
            return

        self.delete_chunks_if_unreferenced([str(chunk["hash"]) for chunk in manifest.chunks])
