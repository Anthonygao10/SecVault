from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from wiki_tool.operations import (
    DraftApplyError,
    apply_draft,
    audit_vault,
    build_catalog,
    find_uncovered_sources,
    lint_vault,
    query_catalog,
)

FIXTURES = Path(__file__).parent / "fixtures"


def add_bad_fixture(vault: Path, fixture_name: str, destination: str) -> Path:
    target = vault / destination
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES / "bad" / fixture_name, target)
    return target


def test_good_fixture_passes_lint(good_vault: Path) -> None:
    result = lint_vault(good_vault)

    assert result.ok, result.errors
    assert result.checked_notes == 3


def test_catalog_contains_body_text(good_vault: Path) -> None:
    catalog = build_catalog(good_vault)

    vulnerability = next(entry for entry in catalog["notes"] if entry["type"] == "vulnerability")
    assert "parameterized queries" in vulnerability["body"]


def test_coverage_reports_unlinked_raw_sources(good_vault: Path) -> None:
    source = good_vault / "raw" / "sources" / "source-2026-09-30-unlinked.md"
    source.write_text(
        (good_vault / "raw" / "sources" / "source-2026-09-30-scan.md").read_text(),
        encoding="utf-8",
    )

    uncovered = find_uncovered_sources(good_vault)

    assert uncovered == ["raw/sources/source-2026-09-30-unlinked.md"]


def test_missing_front_matter_fails(good_vault: Path) -> None:
    add_bad_fixture(
        good_vault,
        "missing-front-matter.md",
        "wiki/concepts/concept-missing-front-matter.md",
    )

    result = lint_vault(good_vault)

    assert any("missing YAML front matter" in error for error in result.errors)


def test_unknown_tag_fails(good_vault: Path) -> None:
    add_bad_fixture(good_vault, "unknown-tag.md", "wiki/concepts/concept-unknown-tag.md")

    result = lint_vault(good_vault)

    assert any("unknown tag `not-approved`" in error for error in result.errors)


def test_broken_link_fails(good_vault: Path) -> None:
    add_bad_fixture(good_vault, "broken-link.md", "wiki/concepts/concept-broken-link.md")

    result = lint_vault(good_vault)

    assert any("broken wiki link `[[missing-note]]`" in error for error in result.errors)


def test_missing_source_citation_fails(good_vault: Path) -> None:
    add_bad_fixture(
        good_vault,
        "missing-source.md",
        "wiki/concepts/concept-missing-source.md",
    )

    result = lint_vault(good_vault)

    assert any("must cite at least one raw source" in error for error in result.errors)


def test_modified_raw_file_fails_hash_validation(good_vault: Path) -> None:
    source = good_vault / "raw" / "sources" / "source-2026-09-30-scan.md"
    source.write_text(source.read_text() + "\nAdditional untracked evidence.\n", encoding="utf-8")

    result = lint_vault(good_vault)

    assert any("raw content hash does not match manifest" in error for error in result.errors)


def test_secret_like_value_fails(good_vault: Path) -> None:
    add_bad_fixture(
        good_vault,
        "secret.md",
        "raw/sources/source-2026-09-30-secret.md",
    )

    result = lint_vault(good_vault)

    assert any("secret-like value detected" in error for error in result.errors)


def test_query_finds_body_only_match(good_vault: Path) -> None:
    build_catalog(good_vault)

    results = query_catalog(good_vault, "parameterized", limit=5)

    assert results
    assert results[0]["path"] == "wiki/vulnerabilities/vuln-sql-injection.md"


def draft_text(title: str, finding_id: str) -> str:
    return f"""---
type: vulnerability
title: "{title}"
tags:
  - vulnerability
  - cwe-89-sql-injection
created: 2026-09-30
updated: 2026-09-30
sources:
  - "[[raw/sources/source-2026-09-30-scan]]"
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

This draft documents a parameterized-query remediation.
"""


def test_apply_moves_approved_draft_and_audits(good_vault: Path) -> None:
    draft = good_vault / "proposed" / "vuln-new-finding.md"
    draft.write_text(draft_text("New SQL injection finding", "demo:new"), encoding="utf-8")

    result = apply_draft(good_vault, draft)

    assert not draft.exists()
    assert (good_vault / "wiki" / "vulnerabilities" / "vuln-new-finding.md").exists()
    assert result["audit"]["status"] == "passed"
    assert (good_vault / "logs" / "wiki-log.md").exists()


def test_apply_refuses_overwrite(good_vault: Path) -> None:
    draft = good_vault / "proposed" / "vuln-sql-injection.md"
    draft.write_text(draft_text("Replacement", "demo:replacement"), encoding="utf-8")

    with pytest.raises(DraftApplyError, match="refusing to overwrite"):
        apply_draft(good_vault, draft)

    assert draft.exists()
    assert "SQL injection in search endpoint" in (
        good_vault / "wiki" / "vulnerabilities" / "vuln-sql-injection.md"
    ).read_text(encoding="utf-8")


def test_audit_runs_all_deterministic_checks(good_vault: Path) -> None:
    result = audit_vault(good_vault)

    assert result["status"] == "passed"
    assert result["catalog_count"] == 3
    assert result["manifest_count"] == 1
    assert result["regression_queries"]["vulnerability"] == 1
