"""Blind indexes and token HMACs. Neither value is reversible."""

from __future__ import annotations

import hashlib
import hmac


def blind_index(index_key: bytes, value: str) -> bytes:
    normalized = value.strip().lower().encode()
    return hmac.new(index_key, normalized, hashlib.sha256).digest()


def token_hmac(pepper: bytes, token: str) -> bytes:
    return hmac.new(pepper, token.encode(), hashlib.sha256).digest()
