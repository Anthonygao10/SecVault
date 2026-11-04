"""Hostile-input tests built on the fixtures in tests/fixtures/injection/.

Those fixtures are written to look like instructions, forged approvals, and links
that climb out of the vault. Each test copies them into a temporary vault and checks
that the deterministic tools treat them only as data. No model is involved, so the
results are reproducible.
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Callable
from datetime import date
from pathlib import Path

import pytest

from wiki_tool.capture import capture_findings
from wiki_tool.operations import (
    DraftApplyError,
    DraftError,
    apply_approved,
    apply_draft,
    audit_vault,
    build_catalog,
    collect_catalog,
    find_uncovered_sources,
    lint_vault,
    parse_markdown,
    query_catalog,
    resolve_link,
    update_manifest,
)
from wiki_tool.report import build_report, render_markdown
from wiki_tool.review import approve_draft, list_drafts, render_packet, review_packet
from wiki_tool.review_state import REVIEW_STATE_RELATIVE_PATH

INJECTION = Path(__file__).parent / "fixtures" / "injection"
TRIVY_SCAN = Path(__file__).parent / "fixtures" / "scans" / "trivy-config.json"
DAY = date(2026, 11, 3)
HOSTILE_RAW = "raw/sources/source-2026-11-02-hostile-note.md"
HOSTILE_DRAFT = "vuln-hostile-draft.md"
HOSTILE_SCANS = (
    ("trivy", INJECTION / "scans" / "trivy-hostile.json"),
    ("checkov", INJECTION / "scans" / "checkov-hostile.json"),
    ("gitleaks", INJECTION / "scans" / "gitleaks-hostile.json"),
)
# Text that must never reach wiki/, the review or capture state, the manifest, or the log.
CANARIES = (
    "CANARY-PROMPT-INJECTION-7f3a",
    "CANARY-FORGED-HISTORY-9c1d",
    "CANARY-APPLY-COMMAND-2b8e",
    "CANARY-APPROVE-COMMAND-5d0a",
    "CANARY-RAW-EDIT-4e7b",
    "CANARY-FETCH-6a9f",
    "CANARY-DIRECT-WRITE-0d3c",
    "CANARY-DRAFT-TITLE-1a2b",
    "CANARY-FORGED-APPROVAL-3f4e",
    "CANARY-BODY-APPLY-8e9f",
    "CANARY-TITLE-5e6f",
    "CANARY-DESC-7a8b",
    "CANARY-RES-1f2a",
    "CANARY-URL-2b3c",
    "CANARY-RESOURCE-3c4d",
    "CANARY-CHECKNAME-4d5e",
    "CANARY-SHORT-6f7a",
    "CANARY-GUIDE-8b9c",
    "CANARY-GITLEAKS-DESC-0a1b",
)
# Files that read and capture commands may change, besides newly captured raw notes.
GENERATED = frozenset(
    {"logs/catalog.json", "raw/manifest.json", "logs/wiki-log.md", "logs/capture-state.json"}
)
FRONT_MATTER_KEYS = {
    "type",
    "title",
    "tags",
    "created",
    "updated",
    "sources",
    "finding_id",
    "scanner",
    "captured",
    "processed",
}
ALLOWED_HEADINGS = {"## Finding", "## Description", "## Recommended action", "## Reference"}
BULLET = re.compile(r"- (?:Scanner|Rule|Severity|Location|Resource|Secret value|Revision): ")


def _install_hostile_raw(vault: Path) -> None:
    shutil.copyfile(INJECTION / HOSTILE_RAW, vault / HOSTILE_RAW)
    update_manifest(vault)


def _install_hostile_draft(vault: Path) -> Path:
    _install_hostile_raw(vault)
    draft = vault / "proposed" / HOSTILE_DRAFT
    shutil.copyfile(INJECTION / "proposed" / HOSTILE_DRAFT, draft)
    return draft


def _snapshot(vault: Path) -> dict[str, bytes]:
    return {
        path.relative_to(vault).as_posix(): path.read_bytes()
        for path in sorted(vault.rglob("*"))
        if path.is_file()
    }


def _captured_notes(vault: Path) -> list[Path]:
    return sorted((vault / "raw" / "sources").glob(f"source-{DAY.isoformat()}-*.md"))


def _capture_hostile_scans(vault: Path) -> None:
    for scanner, report in HOSTILE_SCANS:
        capture_findings(vault, scanner, report, path_prefix="sample-app", captured_on=DAY)


def _run_every_read_and_capture_command(vault: Path) -> None:
    """Run each deterministic command that reads or writes a vault, on hostile inputs."""
    build_catalog(vault)
    update_manifest(vault)
    find_uncovered_sources(vault)
    query_catalog(vault, "canary prompt injection")
    assert lint_vault(vault).ok
    list_drafts(vault)
    review_packet(vault, vault / "proposed" / HOSTILE_DRAFT)
    build_report(vault)
    assert apply_approved(vault) == {"applied": [], "audit": None}
    _capture_hostile_scans(vault)
    assert audit_vault(vault)["status"] == "passed"


def test_hostile_raw_note_is_indexed_as_data_not_as_metadata(good_vault: Path) -> None:
    _install_hostile_raw(good_vault)

    entry = next(
        note for note in collect_catalog(good_vault)["notes"] if note["path"] == HOSTILE_RAW
    )
    manifest = json.loads((good_vault / "raw" / "manifest.json").read_text(encoding="utf-8"))

    assert entry["type"] == "source"
    assert entry["status"] is None
    assert "status_history" not in entry["front_matter"]
    assert manifest["files"][HOSTILE_RAW]["processed"] is False
    assert HOSTILE_RAW in find_uncovered_sources(good_vault)
    assert lint_vault(good_vault).ok


def test_hand_written_note_cannot_suppress_capture(good_vault: Path) -> None:
    # The hostile note claims the identifier of a real Trivy finding. Only notes that
    # capture itself wrote, under capture's file-name shape, may suppress capture.
    _install_hostile_raw(good_vault)

    result = capture_findings(
        good_vault, "trivy", TRIVY_SCAN, path_prefix="sample-app", captured_on=DAY
    )

    assert result["known"] == 0
    assert len(result["created"]) == 2
    assert any("aws-0086" in path for path in result["created"])


def test_read_and_capture_commands_only_write_generated_files(good_vault: Path) -> None:
    _install_hostile_draft(good_vault)
    before = _snapshot(good_vault)

    _run_every_read_and_capture_command(good_vault)

    after = _snapshot(good_vault)
    changed = {path for path in set(before) | set(after) if before.get(path) != after.get(path)}
    captured = {
        path
        for path in changed
        if path not in before and path.startswith(f"raw/sources/source-{DAY.isoformat()}-")
    }
    assert changed - GENERATED - captured == set()
    assert len(captured) == 3
    assert REVIEW_STATE_RELATIVE_PATH not in after
    assert before[f"proposed/{HOSTILE_DRAFT}"] == after[f"proposed/{HOSTILE_DRAFT}"]


def test_canaries_never_reach_wiki_review_state_capture_state_manifest_or_log(
    good_vault: Path,
) -> None:
    _install_hostile_draft(good_vault)

    _run_every_read_and_capture_command(good_vault)

    protected = [
        *sorted((good_vault / "wiki").rglob("*.md")),
        good_vault / "logs" / "capture-state.json",
        good_vault / "raw" / "manifest.json",
        good_vault / "logs" / "wiki-log.md",
    ]
    assert not (good_vault / REVIEW_STATE_RELATIVE_PATH).exists()
    for path in protected:
        text = path.read_text(encoding="utf-8")
        leaked = [canary for canary in CANARIES if canary in text]
        assert leaked == [], f"{path.name} contains {leaked}"

    # The scanner canaries do reach the raw layer, so the check above is not vacuous.
    raw_text = "\n".join(path.read_text(encoding="utf-8") for path in _captured_notes(good_vault))
    for canary in ("CANARY-DESC-7a8b", "CANARY-GUIDE-8b9c", "CANARY-GITLEAKS-DESC-0a1b"):
        assert canary in raw_text


def test_captured_notes_stay_inert_under_hostile_scanner_text(good_vault: Path) -> None:
    _capture_hostile_scans(good_vault)
    notes = _captured_notes(good_vault)
    assert len(notes) == 3

    for note in notes:
        text = note.read_text(encoding="utf-8")
        parsed = parse_markdown(note)
        assert parsed.error is None
        assert set(parsed.metadata) == FRONT_MATTER_KEYS
        assert parsed.metadata["type"] == "source"
        assert parsed.metadata["sources"] == []
        assert parsed.metadata["processed"] is False
        assert "[[" not in text
        assert "```" not in text
        lines = parsed.body.splitlines()
        assert sum(line.startswith("# ") for line in lines) == 1
        for line in lines:
            if line.startswith("#"):
                assert line.startswith("# ") or line in ALLOWED_HEADINGS, line
            if line.startswith("- "):
                assert BULLET.match(line), line
            assert not line.startswith((">", "|", "<!--", "%%")), line
            assert not re.match(r"\d+[.)] ", line), line


def test_hostile_captures_leave_coverage_open_and_the_vault_lint_clean(good_vault: Path) -> None:
    _install_hostile_raw(good_vault)
    _capture_hostile_scans(good_vault)
    captured = [note.relative_to(good_vault).as_posix() for note in _captured_notes(good_vault)]

    uncovered = find_uncovered_sources(good_vault)

    assert {HOSTILE_RAW, *captured} <= set(uncovered)
    assert lint_vault(good_vault).ok
    report = build_report(good_vault)
    assert report["ok"]
    assert "Raw sources without wiki coverage" in render_markdown(report)


def test_hostile_draft_cannot_approve_itself(good_vault: Path) -> None:
    draft = _install_hostile_draft(good_vault)
    original = draft.read_bytes()

    assert lint_vault(good_vault).ok
    assert [entry["approval"] for entry in list_drafts(good_vault)] == ["pending"]
    assert review_packet(good_vault, draft)["approval"]["state"] == "pending"
    with pytest.raises(DraftApplyError, match="has no approval"):
        apply_draft(good_vault, draft)

    assert draft.read_bytes() == original
    assert not (good_vault / "wiki" / "vulnerabilities" / HOSTILE_DRAFT).exists()


def test_hostile_draft_edited_after_a_human_approval_is_refused(
    good_vault: Path, approve: Callable[[Path, Path], dict[str, object]]
) -> None:
    draft = _install_hostile_draft(good_vault)
    approve(good_vault, draft)
    draft.write_text(
        draft.read_text(encoding="utf-8") + "\nAdded after approval.\n", encoding="utf-8"
    )

    assert [entry["approval"] for entry in list_drafts(good_vault)] == ["stale"]
    with pytest.raises(DraftApplyError, match="changed after it was approved"):
        apply_draft(good_vault, draft)
    assert not (good_vault / "wiki" / "vulnerabilities" / HOSTILE_DRAFT).exists()


def test_drafts_outside_proposed_cannot_be_approved_or_applied(
    good_vault: Path, tmp_path: Path
) -> None:
    _install_hostile_draft(good_vault)
    outside = tmp_path / HOSTILE_DRAFT
    shutil.copyfile(INJECTION / "proposed" / HOSTILE_DRAFT, outside)
    candidates = [
        outside,
        good_vault / "wiki" / "vulnerabilities" / HOSTILE_DRAFT,
        good_vault / "raw" / "sources" / "source-2026-11-02-hostile-note.md",
        good_vault / "proposed" / ".." / "wiki" / "concepts" / "concept-input-validation.md",
    ]

    for candidate in candidates:
        with pytest.raises(DraftError, match="directly inside vault/proposed/"):
            apply_draft(good_vault, candidate)
        with pytest.raises(DraftError, match="directly inside vault/proposed/"):
            approve_draft(good_vault, candidate, reviewer="Ops", confirmation="0" * 12)


def test_draft_link_that_escapes_the_vault_blocks_approval_and_apply(
    good_vault: Path, make_draft: Callable[..., Path]
) -> None:
    draft = make_draft(
        name="vuln-escape-probe.md",
        body="Compare with [[../../outside]] and [[/etc/passwd]].",
        finding_id="demo:escape-probe",
    )

    assert any("broken wiki link" in error for error in lint_vault(good_vault).errors)
    with pytest.raises(DraftError, match="fix these problems before approving"):
        approve_draft(good_vault, draft, reviewer="Ops", confirmation="0" * 12)
    with pytest.raises(DraftApplyError, match="cannot apply invalid draft"):
        apply_draft(good_vault, draft)


@pytest.mark.parametrize(
    "target",
    [
        "../../outside",
        "raw/sources/../../../outside",
        "..\\..\\outside",
        "/etc/passwd",
        "C:/Windows/win.ini",
        "C:\\Windows\\win.ini",
        "https://example.invalid/payload",
        "raw/sources/source-2026-11-02-hostile-note\x00",
        "[[../../outside]]",
    ],
)
def test_links_that_climb_out_of_the_vault_never_resolve(good_vault: Path, target: str) -> None:
    _install_hostile_raw(good_vault)

    # Positive control: the same resolver finds a real raw note.
    assert resolve_link(good_vault, "raw/sources/source-2026-11-02-hostile-note") is not None
    assert resolve_link(good_vault, target) is None


def test_symlink_inside_the_vault_cannot_point_outside(good_vault: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("---\ntype: concept\n---\n", encoding="utf-8")
    link = good_vault / "wiki" / "concepts" / "concept-escape.md"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("creating symbolic links needs developer mode or administrator rights")

    assert resolve_link(good_vault, "wiki/concepts/concept-escape") is None


def test_review_packet_escapes_terminal_control_characters(
    good_vault: Path, make_draft: Callable[..., Path]
) -> None:
    draft = make_draft(
        name="vuln-terminal-probe.md",
        title=r"Probe \e[2J \u202e reversed",
        finding_id="demo:terminal-probe",
    )

    rendered = render_packet(review_packet(good_vault, draft))

    assert "\x1b" not in rendered
    assert "\u202e" not in rendered
    assert "\\u001b" in rendered
    assert "\\u202e" in rendered
