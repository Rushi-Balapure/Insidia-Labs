"""Replace secret-shaped substrings before anything is stored or logged."""

from __future__ import annotations

import re

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[AWS_ACCESS_KEY]"),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
        "[PRIVATE_KEY]",
    ),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "[GITHUB_TOKEN]"),
    (re.compile(r"sk_live_[A-Za-z0-9]{10,}"), "[STRIPE_KEY]"),
)


def redact(text: str) -> str:
    redacted = text
    for pattern, token in _PATTERNS:
        redacted = pattern.sub(token, redacted)
    return redacted
