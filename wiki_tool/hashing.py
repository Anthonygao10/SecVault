"""Content hashes shared by the raw manifest and the review loop.

Approvals and manifest records must agree on what a file's digest is, so the
functions live in one place. Text files are hashed with LF line endings so that
a Windows checkout with CRLF endings produces the same digest as the committed file.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

TEXT_SUFFIXES = {".md", ".json", ".txt", ".yaml", ".yml"}


def normalized_digest(data: bytes) -> str:
    """Hash text bytes after folding CRLF line endings to LF."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def sha256_file(path: Path) -> str:
    """Hash a file; text files are hashed with LF endings so checkouts agree.

    Git on Windows may rewrite line endings on checkout. Normalizing CRLF to LF
    keeps hashes stable across operating systems without hiding any other change.
    """
    if path.suffix.lower() in TEXT_SUFFIXES:
        return normalized_digest(path.read_bytes())
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
