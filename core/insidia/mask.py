"""Mask secret-shaped text before it is stored or printed."""

from __future__ import annotations

import hashlib
import re

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GITHUB_TOKEN", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("STRIPE_KEY", re.compile(r"sk_live_[A-Za-z0-9]{10,}")),
    ("OPENAI_KEY", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("BEARER", re.compile(r"Bearer [A-Za-z0-9._\-]{8,}")),
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
)


def mask(text: str) -> str:
    masked = text
    for kind, pattern in _PATTERNS:

        def replace(match: re.Match[str], kind: str = kind) -> str:
            return _token(kind, match.group(0))

        masked = pattern.sub(replace, masked)
    return masked


def _token(kind: str, secret: str) -> str:
    fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:8]
    return f"[{kind} len={len(secret)} fp={fingerprint}]"
