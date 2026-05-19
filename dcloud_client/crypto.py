"""Cryptographic primitives used by the MVP client."""

from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_node_id(public_key_bytes: bytes) -> str:
    """Derive a stable node id from an Ed25519 public key."""
    return sha256_hex(public_key_bytes)


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_to_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def public_key_to_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def private_key_from_bytes(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_from_bytes(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def sign_bytes(private_key: Ed25519PrivateKey, data: bytes) -> str:
    return base64.b64encode(private_key.sign(data)).decode("ascii")


def verify_signature(public_key_bytes: bytes, data: bytes, signature_b64: str) -> bool:
    try:
        public_key_from_bytes(public_key_bytes).verify(base64.b64decode(signature_b64), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))
