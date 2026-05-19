"""Local node identity management."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import logging
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import b64encode, derive_node_id, generate_private_key, private_key_from_bytes, private_key_to_bytes, public_key_to_bytes

LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class NodeIdentity:
    private_key: Ed25519PrivateKey
    public_key_bytes: bytes
    node_id: str

    @property
    def public_key_b64(self) -> str:
        return b64encode(self.public_key_bytes)


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

    def _write_private_key(self, raw: bytes) -> None:
        tmp = self.private_key_file.with_suffix(".tmp")
        tmp.write_bytes(raw)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            LOG.debug("Could not chmod private key on this platform", exc_info=True)
        tmp.replace(self.private_key_file)
