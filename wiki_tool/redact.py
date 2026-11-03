"""Secret detection and redaction for scanner-derived evidence.

Capture removes secret-like values before anything reaches the raw layer, and
lint uses the same patterns to flag secret-like text anywhere in the vault. The
patterns favor false positives: an over-redacted harmless string is cheap, while
a missed credential is not.
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(
        r"(?im)^\s*[A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|"
        r"PASSWORD|SECRET)[A-Z0-9_]*\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}"
    ),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}\b"),
)
# Scanner messages are flattened to a single line before they are stored, so an
# assignment must also match away from the start of a line. The keyword may not sit
# inside a larger identifier, so rule names such as `generic-api-key:` do not match.
INLINE_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])[A-Z0-9_]*(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"password|passwd|secret|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}"
)
_DETECTORS = (PRIVATE_KEY_BLOCK, *SECRET_PATTERNS, INLINE_ASSIGNMENT)


def contains_secret(text: str) -> bool:
    """Return True when text holds a value that redaction would remove."""
    return any(pattern.search(text) for pattern in _DETECTORS)


def redact_text(text: str) -> str:
    """Replace every secret-like value in text with a fixed placeholder."""
    redacted = PRIVATE_KEY_BLOCK.sub(REDACTED, text)
    for pattern in (*SECRET_PATTERNS, INLINE_ASSIGNMENT):
        redacted = pattern.sub(REDACTED, redacted)
    return redacted
