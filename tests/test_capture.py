from __future__ import annotations

import codecs
import copy
import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from wiki_tool.capture import (
    CaptureError,
    Finding,
    _captured_note_ids,
    _location,
    _markdown_safe,
    capture_findings,
    normalize_path,
    render_note,
    stable_finding_id,
)
from wiki_tool.cli import main
from wiki_tool.operations import lint_vault, parse_note_text
from wiki_tool.safe_text import inline_text

SCANS = Path(__file__).parent / "fixtures" / "scans"
DAY = date(2026, 11, 3)
FAKE_SECRET = "FAKE-SECRET-VALUE-1234567890"
FAKE_AWS_KEY = "AKIAXXXXXXXXXXXXXXXX"
CODE_MARKER = "FAKE-CODE-SNIPPET-MARKER"


def _report(name: str) -> Any:
    return json.loads((SCANS / name).read_text(encoding="utf-8"))


def _write_json(path: Path, data: Any) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _capture(vault: Path, scanner: str, report: Path) -> dict[str, Any]:
    return capture_findings(vault, scanner, report, path_prefix="sample-app", captured_on=DAY)


def _raw_notes(vault: Path) -> list[Path]:
    return sorted((vault / "raw" / "sources").glob(f"source-{DAY.isoformat()}-*.md"))


def _state(vault: Path) -> dict[str, Any]:
    return json.loads((vault / "logs" / "capture-state.json").read_text(encoding="utf-8"))


def _vault_text(vault: Path) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8") for path in vault.rglob("*") if path.is_file()
    )


def _trivy_without(report: dict[str, Any], rule_id: str) -> dict[str, Any]:
    reduced = copy.deepcopy(report)
    for result in reduced["Results"]:
        if "Misconfigurations" in result:
            result["Misconfigurations"] = [
                item for item in result["Misconfigurations"] if item["ID"] != rule_id
            ]
    return reduced


def test_each_scanner_is_captured_as_raw_notes(good_vault: Path) -> None:
    trivy = _capture(good_vault, "trivy", SCANS / "trivy-config.json")
    checkov = _capture(good_vault, "checkov", SCANS / "checkov-report.json")
    gitleaks = _capture(good_vault, "gitleaks", SCANS / "gitleaks-report.json")

    assert [len(r["created"]) for r in (trivy, checkov, gitleaks)] == [2, 2, 1]
    assert len(_raw_notes(good_vault)) == 5
    assert lint_vault(good_vault).ok


def test_passing_checks_are_not_captured(good_vault: Path) -> None:
    result = _capture(good_vault, "trivy", SCANS / "trivy-config.json")

    assert result["findings"] == 2
    assert not any("AWS-0001" in path for path in result["created"])


def test_rerun_creates_nothing_and_leaves_evidence_byte_identical(good_vault: Path) -> None:
    report = SCANS / "trivy-config.json"
    _capture(good_vault, "trivy", report)
    notes_before = {path: path.read_bytes() for path in _raw_notes(good_vault)}
    manifest_before = (good_vault / "raw" / "manifest.json").read_bytes()

    result = _capture(good_vault, "trivy", report)

    assert result["created"] == []
    assert result["known"] == 2
    assert {path: path.read_bytes() for path in _raw_notes(good_vault)} == notes_before
    assert (good_vault / "raw" / "manifest.json").read_bytes() == manifest_before


def test_moving_a_finding_to_another_line_keeps_its_identity(
    good_vault: Path, tmp_path: Path
) -> None:
    report = _report("trivy-config.json")
    _capture(good_vault, "trivy", _write_json(tmp_path / "first.json", report))
    moved = copy.deepcopy(report)
    for result in moved["Results"]:
        for item in result.get("Misconfigurations", []):
            item["CauseMetadata"]["StartLine"] += 40

    result = _capture(good_vault, "trivy", _write_json(tmp_path / "moved.json", moved))

    assert result["created"] == []
    assert result["known"] == 2


def test_secrets_and_local_paths_never_reach_the_vault(good_vault: Path) -> None:
    _capture(good_vault, "trivy", SCANS / "trivy-config.json")
    _capture(good_vault, "checkov", SCANS / "checkov-report.json")
    _capture(good_vault, "gitleaks", SCANS / "gitleaks-report.json")

    text = _vault_text(good_vault)

    for forbidden in (
        FAKE_SECRET,
        FAKE_AWS_KEY,
        CODE_MARKER,
        "/home/runner",
        "file_abs_path",
        "code_block",
    ):
        assert forbidden not in text, forbidden
    assert "[REDACTED]" in text
    assert lint_vault(good_vault).ok


def test_private_key_blocks_in_scanner_messages_are_redacted(
    good_vault: Path, tmp_path: Path
) -> None:
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    footer = "-----END " + "RSA PRIVATE KEY-----"
    report = _report("trivy-config.json")
    report["Results"][1]["Misconfigurations"][0]["Message"] = (
        f"Key material {header} MIIFAKEBODY {footer} exposed"
    )

    _capture(good_vault, "trivy", _write_json(tmp_path / "pem.json", report))

    text = _vault_text(good_vault)
    assert "MIIFAKEBODY" not in text
    assert "PRIVATE KEY" not in text


def test_missing_findings_become_candidate_fixed_and_can_reopen(
    good_vault: Path, tmp_path: Path
) -> None:
    full = _report("trivy-config.json")
    _capture(good_vault, "trivy", _write_json(tmp_path / "full.json", full))

    reduced = _trivy_without(full, "AWS-0107")
    missing = _capture(good_vault, "trivy", _write_json(tmp_path / "reduced.json", reduced))

    assert len(missing["candidate_fixed"]) == 1
    assert sorted(entry["status"] for entry in _state(good_vault)["findings"].values()) == [
        "candidate_fixed",
        "open",
    ]

    back = _capture(good_vault, "trivy", _write_json(tmp_path / "again.json", full))

    assert back["created"] == []
    assert len(back["reopened"]) == 1
    assert all(entry["status"] == "open" for entry in _state(good_vault)["findings"].values())


def test_absence_only_marks_findings_from_the_same_scanner(
    good_vault: Path, tmp_path: Path
) -> None:
    _capture(good_vault, "gitleaks", SCANS / "gitleaks-report.json")
    empty = _write_json(tmp_path / "empty-trivy.json", {"SchemaVersion": 2, "Results": []})

    result = _capture(good_vault, "trivy", empty)

    assert result["candidate_fixed"] == []
    assert all(entry["status"] == "open" for entry in _state(good_vault)["findings"].values())


def test_absence_respects_the_path_prefix(good_vault: Path, tmp_path: Path) -> None:
    _capture(good_vault, "trivy", SCANS / "trivy-config.json")
    empty = _write_json(tmp_path / "empty.json", {"Results": []})

    other = capture_findings(good_vault, "trivy", empty, path_prefix="infra", captured_on=DAY)
    same = capture_findings(good_vault, "trivy", empty, path_prefix="sample-app", captured_on=DAY)

    assert other["candidate_fixed"] == []
    assert len(same["candidate_fixed"]) == 2


def test_checkov_accepts_utf16_output_with_bom(good_vault: Path, tmp_path: Path) -> None:
    path = tmp_path / "checkov-utf16.json"
    path.write_bytes(json.dumps(_report("checkov-report.json")).encode("utf-16"))

    result = _capture(good_vault, "checkov", path)

    assert path.read_bytes().startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE))
    assert len(result["created"]) == 2


def test_gitleaks_null_report_means_no_leaks(good_vault: Path, tmp_path: Path) -> None:
    path = tmp_path / "null.json"
    path.write_text("null", encoding="utf-8")

    result = _capture(good_vault, "gitleaks", path)

    assert result["findings"] == 0
    assert result["candidate_fixed"] == []


@pytest.mark.parametrize(
    ("scanner", "payload"),
    [
        ("trivy", {"Something": []}),
        ("checkov", {"unexpected": True}),
        ("gitleaks", {"not": "a list"}),
    ],
)
def test_unexpected_report_shapes_are_rejected(
    good_vault: Path, tmp_path: Path, scanner: str, payload: Any
) -> None:
    path = _write_json(tmp_path / "bad.json", payload)

    with pytest.raises(CaptureError):
        _capture(good_vault, scanner, path)
    assert _raw_notes(good_vault) == []


def test_absolute_windows_paths_are_rejected(good_vault: Path, tmp_path: Path) -> None:
    report = _report("checkov-report.json")
    report["results"]["failed_checks"][0]["file_path"] = "C:\\Users\\dev\\main.tf"

    with pytest.raises(CaptureError, match="absolute path"):
        _capture(good_vault, "checkov", _write_json(tmp_path / "abs.json", report))


def test_vault_that_fails_lint_is_not_extended(good_vault: Path) -> None:
    source = good_vault / "raw" / "sources" / "source-2026-09-30-scan.md"
    source.write_text("tampered\n", encoding="utf-8")

    with pytest.raises(CaptureError, match="does not lint cleanly"):
        _capture(good_vault, "trivy", SCANS / "trivy-config.json")

    assert _raw_notes(good_vault) == []
    assert not (good_vault / "logs" / "capture-state.json").exists()


def test_stable_identifier_scheme_is_fixed() -> None:
    # Changing this scheme gives every captured finding a new identity, so the value
    # below is a contract. Update it only with a deliberate schema decision.
    identifier = stable_finding_id(
        "trivy",
        "AWS-0086",
        "sample-app/main.tf",
        "aws_s3_bucket_public_access_block.public_demo",
    )

    assert identifier == "101aad4318ba"


@pytest.mark.parametrize(
    ("raw", "prefix", "expected"),
    [
        ("main.tf", "sample-app", "sample-app/main.tf"),
        ("/main.tf", "sample-app", "sample-app/main.tf"),
        ("\\main.tf", "sample-app", "sample-app/main.tf"),
        ("./main.tf", None, "main.tf"),
        ("sample-app/app.py", "sample-app", "sample-app/app.py"),
        (".", "sample-app", "sample-app"),
    ],
)
def test_paths_are_normalized_once(raw: str, prefix: str | None, expected: str) -> None:
    assert normalize_path(raw, prefix) == expected


def test_cli_capture_reports_json_and_refuses_a_tampered_vault(
    good_vault: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments = [
        "capture",
        "--vault",
        str(good_vault),
        "--scanner",
        "gitleaks",
        "--input",
        str(SCANS / "gitleaks-report.json"),
        "--path-prefix",
        "sample-app",
        "--date",
        DAY.isoformat(),
        "--json",
    ]
    assert main(arguments) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["created"] and payload["lint"]["ok"]

    (good_vault / "raw" / "sources" / "source-2026-09-30-scan.md").write_text(
        "tampered\n", encoding="utf-8"
    )
    assert main(arguments) == 2


# --- Hardening of text that scanners control ---------------------------------

BENIGN_BODY = """# Trivy AWS-0086: S3 public access

Capture mode: normalized and redacted Trivy output, written by `wiki_tool capture`.
Raw evidence: do not edit. Interpretation belongs in a proposed wiki note.

## Finding

- Scanner: Trivy
- Rule: `AWS-0086`
- Severity: HIGH
- Location: `sample-app/main.tf` line 25
- Resource: `aws_s3_bucket_public_access_block.public_demo`

## Description

Public access is allowed.

## Recommended action

Enable the block.

## Reference

https://example.invalid/AWS-0086"""


def test_inline_text_flattens_lines_and_defuses_markup() -> None:
    assert inline_text("a\n## b `c` [[d]]") == "a ## b 'c' [ [d] ]"
    assert inline_text("  spaced\t\tout  ") == "spaced out"
    assert inline_text("bell\x07and\x1b[31m") == "bell and [31m"


def test_markdown_safe_neutralises_block_starts() -> None:
    assert _markdown_safe("# Heading") == "\\# Heading"
    assert _markdown_safe("- item") == "\\- item"
    assert _markdown_safe("> quote") == "\\> quote"
    assert _markdown_safe("| a | b |") == "\\| a | b |"
    assert _markdown_safe("1. first") == "1\\. first"
    assert _markdown_safe("<!-- hidden") == "&lt;!-- hidden"
    assert _markdown_safe("%% hidden %%") == "% % hidden % %"
    assert _markdown_safe("plain text") == "plain text"


def test_location_is_one_code_span_with_sorted_lines() -> None:
    assert _location("sample-app/main.tf", [25]) == "`sample-app/main.tf` line 25"
    assert _location("sample-app/main.tf", [30, 25]) == "`sample-app/main.tf` lines 25, 30"
    assert _location("sample-app/main.tf", []) == "`sample-app/main.tf` (line not reported)"
    hostile = _location("sample-app/main.tf`\n## Forged", [7])
    assert hostile == "`sample-app/main.tf' ## Forged` line 7"


def test_benign_finding_renders_the_expected_note() -> None:
    finding = Finding(
        scanner="trivy",
        rule_id="AWS-0086",
        path="sample-app/main.tf",
        subject="aws_s3_bucket_public_access_block.public_demo",
        title="S3 public access",
        severity="HIGH",
        line=25,
        description="Public access is allowed.",
        remediation="Enable the block.",
        reference="https://example.invalid/AWS-0086",
    )

    text = render_note(finding, [25], captured=DAY)
    note = parse_note_text(Path("source.md"), text)

    assert note.error is None
    assert note.metadata["title"] == "Trivy AWS-0086: S3 public access"
    assert note.metadata["finding_id"] == finding.finding_id
    assert note.body.strip() == BENIGN_BODY


def test_only_capture_shaped_notes_suppress_capture(good_vault: Path) -> None:
    raw = good_vault / "raw" / "sources"
    assert _captured_note_ids(good_vault) == set()

    # A note named the way capture names its output, with a matching identifier.
    (raw / "source-2026-11-03-trivy-aws-0086-101aad4318ba.md").write_text(
        '---\nfinding_id: "101aad4318ba"\n---\n', encoding="utf-8"
    )
    # A hand-written note that claims the same identifier under another name.
    (raw / "handwritten-101aad4318ba.md").write_text(
        '---\nfinding_id: "101aad4318ba"\n---\n', encoding="utf-8"
    )
    # A capture-shaped name whose front matter disagrees with the name.
    (raw / "source-2026-11-03-trivy-aws-0107-aaaaaaaaaaaa.md").write_text(
        '---\nfinding_id: "bbbbbbbbbbbb"\n---\n', encoding="utf-8"
    )

    assert _captured_note_ids(good_vault) == {"101aad4318ba"}
