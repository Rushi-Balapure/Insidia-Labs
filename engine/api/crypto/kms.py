"""Key management. Dev uses a local master key. Production uses a KMS that never exports it."""

from __future__ import annotations

import os
from typing import Protocol

from api.crypto.envelope import KEY_LEN, unwrap_key, wrap_key

DEV_MASTER_KEY = b"insidia-dev-master-key-32bytes!!"
DEV_TOKEN_PEPPER = b"insidia-dev-token-pepper-32bytes!"


class Kms(Protocol):
    def wrap(self, dek: bytes) -> bytes: ...

    def unwrap(self, wrapped: bytes) -> bytes: ...

    @property
    def key_ref(self) -> str: ...


class LocalDevKms:
    """Fixed master key for local compose and tests. Refused when dev mode is off."""

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != KEY_LEN:
            raise ValueError("master key must be 256 bits")
        self._master_key = master_key

    def wrap(self, dek: bytes) -> bytes:
        return wrap_key(dek, master_key=self._master_key)

    def unwrap(self, wrapped: bytes) -> bytes:
        return unwrap_key(wrapped, master_key=self._master_key)

    @property
    def key_ref(self) -> str:
        return "local-dev"


def new_data_key() -> bytes:
    return os.urandom(KEY_LEN)
