from __future__ import annotations

import copy
import json
from datetime import date
from pathlib import Path
from typing import Any

from wiki_tool.capture import capture_findings
from wiki_tool.operations import build_catalog
from wiki_tool.report import build_report, render_markdown

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
