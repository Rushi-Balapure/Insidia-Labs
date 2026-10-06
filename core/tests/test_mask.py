import hashlib

from insidia.mask import mask


def test_aws_key_is_masked_with_length_and_fingerprint() -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:8]
    masked = mask(f"token {secret} end")
    assert secret not in masked
    assert masked == f"token [AWS_ACCESS_KEY len={len(secret)} fp={fingerprint}] end"
