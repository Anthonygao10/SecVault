from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from wiki_tool.operations import update_manifest
from wiki_tool.review import approve_draft
from wiki_tool.review_state import draft_fingerprint, short_fingerprint

FIXTURES = Path(__file__).parent / "fixtures"
SOURCE_LINK = "[[raw/sources/source-2026-09-30-scan]]"


@pytest.fixture
def good_vault(tmp_path: Path) -> Path:
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURES / "good", vault)
    shutil.copytree(
        Path(__file__).parents[1] / "vault" / "schema",
        vault / "schema",
    )
    (vault / "proposed").mkdir(exist_ok=True)
    update_manifest(vault)
    return vault


def vulnerability_text(
    title: str,
    finding_id: str,
    *,
    body: str = "This draft documents a parameterized-query remediation.",
) -> str:
    """Return a valid vulnerability draft whose status_history starts with its finding."""
    return f"""---
type: vulnerability
title: "{title}"
tags:
  - vulnerability
  - cwe-89-sql-injection
created: 2026-09-30
updated: 2026-09-30
sources:
  - "{SOURCE_LINK}"
severity: medium
cwe: "CWE-89"
owasp: "A03:2021-Injection"
component: "sample-app/search.py"
status: open
status_history:
  - status: open
    date: 2026-09-30
    ref: "{finding_id}"
    note: "First recorded."
finding_id: "{finding_id}"
fix_commit: null
---

# {title}

{body}
"""


@pytest.fixture
def make_draft(good_vault: Path) -> Callable[..., Path]:
    """Write a valid vulnerability draft into proposed/ (or another folder) and return it."""

    def _make(
        name: str = "vuln-new-finding.md",
        *,
        title: str = "New SQL injection finding",
        finding_id: str = "demo:new",
        body: str = "This draft documents a parameterized-query remediation.",
        folder: str = "proposed",
    ) -> Path:
        directory = good_vault / folder
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        path.write_text(vulnerability_text(title, finding_id, body=body), encoding="utf-8")
        return path

    return _make


@pytest.fixture
def approve() -> Callable[[Path, Path], dict[str, object]]:
    """Approve a draft the way a reviewer would: confirm the short hash of its current bytes."""

    def _approve(vault: Path, draft: Path) -> dict[str, object]:
        confirmation = short_fingerprint(draft_fingerprint(draft))
        return approve_draft(
            vault,
            draft,
            reviewer="Test Reviewer",
            note="reviewed in test",
            confirmation=confirmation,
        )

    return _approve
