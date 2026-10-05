import os
import uuid

import pytest
from api.crypto.envelope import CryptoError, decrypt, encrypt, make_aad
from api.crypto.indexes import blind_index, token_hmac
from api.crypto.kms import DEV_MASTER_KEY, DEV_TOKEN_PEPPER
from api.crypto.redactor import redact
from api.settings import Settings, get_settings


def test_aad_binds_ciphertext_to_the_row() -> None:
    key = b"k" * 32
    aad = make_aad(str(uuid.uuid4()), "tenant_pings", "payload_enc", str(uuid.uuid4()))
    blob = encrypt(b"canary-plaintext", key=key, key_version=1, aad=aad)
    assert b"canary-plaintext" not in blob
    assert decrypt(blob, key=key, aad=aad) == b"canary-plaintext"
    other = make_aad(str(uuid.uuid4()), "tenant_pings", "payload_enc", str(uuid.uuid4()))
    with pytest.raises(CryptoError):
        decrypt(blob, key=key, aad=other)


def test_blind_index_is_stable_and_not_the_value() -> None:
    left = blind_index(b"i" * 32, "  Ops@Example.com ")
    right = blind_index(b"i" * 32, "ops@example.com")
    assert left == right
    assert b"ops@example.com" not in left


def test_token_hmac_needs_the_pepper() -> None:
    assert token_hmac(DEV_TOKEN_PEPPER, "ins_api_secret") != token_hmac(b"p" * 32, "ins_api_secret")


def test_redactor_masks_aws_keys() -> None:
    assert "AKIA" not in redact("key AKIAIOSFODNN7EXAMPLE leaked")


def test_dev_master_key_is_refused_outside_dev(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INSIDIA_DEV_MODE", raising=False)
    monkeypatch.setenv("INSIDIA_MASTER_KEY", DEV_MASTER_KEY.decode())
    get_settings.cache_clear()
    with pytest.raises(RuntimeError):
        Settings().refuse_dev_secrets_outside_dev()
    get_settings.cache_clear()


def test_ping_rejects_a_missing_org() -> None:
    os.environ["INSIDIA_DEV_MODE"] = "true"
    get_settings.cache_clear()
    from workers.common.tasks import ping

    with pytest.raises(ValueError, match="org_id"):
        ping({})  # type: ignore[arg-type]
    get_settings.cache_clear()
