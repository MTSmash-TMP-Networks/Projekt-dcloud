"""Local node identity management."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import logging
import os
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


from .crypto import (
    b64decode,
    b64encode,
    derive_node_id,
    generate_private_key,
    private_key_from_bytes,
    private_key_to_bytes,
    public_key_to_bytes,
)

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class NodeIdentity:
    private_key: Ed25519PrivateKey
    public_key_bytes: bytes
    node_id: str

    @property
    def public_key_b64(self) -> str:
        return b64encode(self.public_key_bytes)


BACKUP_TOKEN_PREFIX = "DCLOUD-BACKUP-v1"
BACKUP_TOKEN_CONTEXT = b"dcloud-backup-token-v1"


def _backup_token_checksum(raw_private_key: bytes, node_id: str) -> str:
    return hashlib.sha256(BACKUP_TOKEN_CONTEXT + raw_private_key + node_id.encode("ascii", errors="strict")).hexdigest()[:16]


def build_backup_token(identity: NodeIdentity) -> str:
    """Return a portable recovery token for the local node identity.

    The token contains the raw Ed25519 private key. Whoever has it can become
    this dcloud node again, so the dashboard must present it as a secret.
    """
    raw = private_key_to_bytes(identity.private_key)
    encoded = b64encode(raw).rstrip("=").replace("+", "-").replace("/", "_")
    checksum = _backup_token_checksum(raw, identity.node_id)
    return f"{BACKUP_TOKEN_PREFIX}:{identity.node_id[:12]}:{encoded}:{checksum}"


def identity_from_backup_token(token: str) -> NodeIdentity:
    """Parse and validate a dcloud backup token."""
    cleaned = str(token or "").strip().replace(" ", "").replace("\n", "")
    parts = cleaned.split(":")
    if len(parts) != 4 or parts[0] != BACKUP_TOKEN_PREFIX:
        raise ValueError("Ungültiger Backup-Token")
    _prefix, node_hint, encoded, checksum = parts
    if not encoded:
        raise ValueError("Backup-Token enthält keinen Schlüssel")
    padded = encoded.replace("-", "+").replace("_", "/")
    padded += "=" * (-len(padded) % 4)
    try:
        raw = b64decode(padded)
        private_key = private_key_from_bytes(raw)
    except Exception as exc:
        raise ValueError("Backup-Token enthält keinen gültigen Schlüssel") from exc
    public_key_bytes = public_key_to_bytes(private_key.public_key())
    node_id = derive_node_id(public_key_bytes)
    if node_hint and not node_id.startswith(node_hint):
        raise ValueError("Backup-Token passt nicht zur enthaltenen Node-ID")
    expected = _backup_token_checksum(raw, node_id)
    if checksum != expected:
        raise ValueError("Backup-Token-Prüfsumme ist ungültig")
    return NodeIdentity(private_key=private_key, public_key_bytes=public_key_bytes, node_id=node_id)


class IdentityManager:
    """Creates and loads the local Ed25519 node identity."""

    def __init__(self, identity_path: Path) -> None:
        self.identity_path = identity_path
        self.private_key_file = identity_path / "node_ed25519.key"

    def load_or_create(self) -> NodeIdentity:
        self.identity_path.mkdir(parents=True, exist_ok=True)
        if self.private_key_file.exists():
            raw = self.private_key_file.read_bytes()
            private_key = private_key_from_bytes(raw)
            LOG.info("Loaded node identity from %s", self.private_key_file)
        else:
            private_key = generate_private_key()
            raw = private_key_to_bytes(private_key)
            self._write_private_key(raw)
            LOG.info("Generated new node identity at %s", self.private_key_file)

        public_key_bytes = public_key_to_bytes(private_key.public_key())
        return NodeIdentity(
            private_key=private_key,
            public_key_bytes=public_key_bytes,
            node_id=derive_node_id(public_key_bytes),
        )

    def import_backup_token(self, token: str) -> NodeIdentity:
        recovered = identity_from_backup_token(token)
        self.identity_path.mkdir(parents=True, exist_ok=True)
        self._write_private_key(private_key_to_bytes(recovered.private_key))
        LOG.info("Imported node identity backup token for node %s", recovered.node_id)
        return recovered

    def _write_private_key(self, raw: bytes) -> None:
        tmp = self.private_key_file.with_suffix(".tmp")
        tmp.write_bytes(raw)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            LOG.debug("Could not chmod private key on this platform", exc_info=True)
        tmp.replace(self.private_key_file)
