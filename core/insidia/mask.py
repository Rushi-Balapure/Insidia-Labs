"""Mask secret-shaped text before it is stored or printed."""

from __future__ import annotations

import contextvars
import hashlib
import re

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GITHUB_TOKEN", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("STRIPE_KEY", re.compile(r"sk_live_[A-Za-z0-9]{10,}")),
    ("OPENAI_KEY", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{10,}")),
    ("BEARER", re.compile(r"Bearer [A-Za-z0-9._\-]{8,}")),
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
)
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_secrets: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar(
    "insidia_secrets", default=()
)


def bind_secrets(values: tuple[str, ...]) -> contextvars.Token[tuple[str, ...]]:
    return _secrets.set(tuple(item for item in values if len(item) >= 8))


def mask(text: str) -> str:
    masked = _ANSI.sub("", text)
    for secret in _secrets.get():
        if secret in masked:
            masked = masked.replace(secret, _token("CONFIGURED", secret))
    for kind, pattern in _PATTERNS:

        def replace(match: re.Match[str], kind: str = kind) -> str:
            return _token(kind, match.group(0))

        masked = pattern.sub(replace, masked)
    return masked


def _token(kind: str, secret: str) -> str:
    fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:8]
    return f"[{kind} len={len(secret)} fp={fingerprint}]"
