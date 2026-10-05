"""AES-256-GCM envelope encryption. The database never sees plaintext."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_VERSION = 1
NONCE_LEN = 12
KEY_LEN = 32
_SEP = b"\x1f"


class CryptoError(Exception):
    """Raised when a ciphertext cannot be decrypted for the requested row."""


def make_aad(org_id: str, table: str, column: str, row_id: str) -> bytes:
    """AAD binds a ciphertext to one org, table, column, and row."""
    parts = [org_id.encode(), table.encode(), column.encode(), row_id.encode()]
    return _SEP.join(parts)


def encrypt(plaintext: bytes, *, key: bytes, key_version: int, aad: bytes) -> bytes:
    if len(key) != KEY_LEN:
        raise CryptoError("data key must be 256 bits")
    if key_version < 1:
        raise CryptoError("key version must be positive")
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    version = ENVELOPE_VERSION.to_bytes(1, "big")
    return version + key_version.to_bytes(4, "big") + nonce + ciphertext


def decrypt(blob: bytes, *, key: bytes, aad: bytes) -> bytes:
    if len(blob) < 1 + 4 + NONCE_LEN + 16:
        raise CryptoError("ciphertext is truncated")
    version = blob[0]
    if version != ENVELOPE_VERSION:
        raise CryptoError("unsupported ciphertext version")
    nonce = blob[5 : 5 + NONCE_LEN]
    ciphertext = blob[5 + NONCE_LEN :]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise CryptoError("decryption failed") from exc


def key_version_of(blob: bytes) -> int:
    if len(blob) < 5:
        raise CryptoError("ciphertext is truncated")
    return int.from_bytes(blob[1:5], "big")


@dataclass(frozen=True)
class WrappedKey:
    """A data key sealed by the master key. Plaintext never leaves the KMS call."""

    blob: bytes


def wrap_key(dek: bytes, *, master_key: bytes) -> bytes:
    return encrypt(dek, key=master_key, key_version=1, aad=b"insidia-key-wrap")


def unwrap_key(blob: bytes, *, master_key: bytes) -> bytes:
    dek = decrypt(blob, key=master_key, aad=b"insidia-key-wrap")
    if len(dek) != KEY_LEN:
        raise CryptoError("unwrapped key is not 256 bits")
    return dek
