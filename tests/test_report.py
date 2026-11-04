from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Any

from wiki_tool.capture import capture_findings
from wiki_tool.operations import build_catalog
from wiki_tool.report import build_report, render_markdown
from wiki_tool.review import reject_draft

SCANS = Path(__file__).parent / "fixtures" / "scans"
DAY = date(2026, 11, 3)


def test_report_passes_on_a_clean_vault(good_vault: Path) -> None:
    build_catalog(good_vault)

    report = build_report(good_vault)

    assert report["ok"]
    assert report["catalog_current"]
    markdown = render_markdown(report)
    assert "PASS" in markdown
    assert "## Captured findings" in markdown


def test_report_flags_a_stale_catalog(good_vault: Path) -> None:
    build_catalog(good_vault)
    note = good_vault / "wiki" / "concepts" / "concept-input-validation.md"
    note.write_text(note.read_text(encoding="utf-8") + "\nNew body text.\n", encoding="utf-8")

    report = build_report(good_vault)

    assert not report["catalog_current"]
    assert "Catalog is stale" in render_markdown(report)


def test_report_lists_candidates_for_fixed(good_vault: Path, tmp_path: Path) -> None:
    full: dict[str, Any] = json.loads((SCANS / "trivy-config.json").read_text(encoding="utf-8"))
    full_path = tmp_path / "full.json"
    full_path.write_text(json.dumps(full), encoding="utf-8")
    capture_findings(good_vault, "trivy", full_path, path_prefix="sample-app", captured_on=DAY)

    reduced = copy.deepcopy(full)
    for result in reduced["Results"]:
        if "Misconfigurations" in result:
            result["Misconfigurations"] = [
                item for item in result["Misconfigurations"] if item["ID"] == "AWS-0086"
            ]
    reduced_path = tmp_path / "reduced.json"
    reduced_path.write_text(json.dumps(reduced), encoding="utf-8")
    capture_findings(good_vault, "trivy", reduced_path, path_prefix="sample-app", captured_on=DAY)

    report = build_report(good_vault)
    markdown = render_markdown(report)

    assert len(report["candidate_fixed"]) == 1
    assert report["candidate_fixed"][0]["rule_id"] == "AWS-0107"
    assert "AWS-0107" in markdown
    assert "A human confirms each `fixed` status" in markdown


def test_report_fails_when_evidence_is_tampered(good_vault: Path) -> None:
    source = good_vault / "raw" / "sources" / "source-2026-09-30-scan.md"
    source.write_text(source.read_text(encoding="utf-8") + "\nTampered.\n", encoding="utf-8")

    report = build_report(good_vault)

    assert not report["ok"]
    assert "FAIL" in render_markdown(report)


def test_report_lists_pending_and_approved_drafts(
    good_vault: Path,
    make_draft: Callable[..., Path],
    approve: Callable[[Path, Path], dict[str, object]],
) -> None:
    draft = make_draft()

    markdown = render_markdown(build_report(good_vault))
    assert "Pending review: 1" in markdown
    assert "`proposed/vuln-new-finding.md` pending" in markdown

    approve(good_vault, draft)
    markdown = render_markdown(build_report(good_vault))
    assert "Pending review: 0" in markdown
    assert "Approved, not yet applied: 1" in markdown
    assert "`proposed/vuln-new-finding.md` approved" in markdown


def test_report_counts_stale_rejected_and_invalid_drafts(
    good_vault: Path,
    make_draft: Callable[..., Path],
    approve: Callable[[Path, Path], dict[str, object]],
) -> None:
    stale = make_draft(name="vuln-stale.md", finding_id="demo:stale")
    approve(good_vault, stale)
    stale.write_text(
        stale.read_text(encoding="utf-8") + "\nEdited after approval.\n", encoding="utf-8"
    )
    rejected = make_draft(name="vuln-rejected.md", finding_id="demo:rejected")
    reject_draft(good_vault, rejected, reviewer="Test Reviewer", reason="Needs a fix commit.")
    make_draft(name="vuln-nested.md", finding_id="demo:nested", folder="proposed/archive")

    report = build_report(good_vault)
    markdown = render_markdown(report)

    assert not report["ok"]
    assert "Stale (changed after approval): 1" in markdown
    assert "Rejected (kept in proposed/): 1" in markdown
    assert "Invalid: 1" in markdown
    assert "`proposed/vuln-stale.md` stale" in markdown
    assert "`proposed/vuln-rejected.md` rejected" in markdown
    assert "`proposed/archive/vuln-nested.md` invalid" in markdown


def test_report_fails_when_review_state_is_unreadable(good_vault: Path) -> None:
    state = good_vault / "logs" / "review-state.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text("{not json", encoding="utf-8")

    report = build_report(good_vault)
    markdown = render_markdown(report)

    assert not report["ok"]
    assert report["review_error"]
    assert "FAIL: review state is unreadable" in markdown
