from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from wiki_tool.cli import _is_interactive, main
from wiki_tool.operations import DraftApplyError, DraftError, apply_draft
from wiki_tool.review import (
    approve_draft,
    clean_single_line,
    list_drafts,
    reject_draft,
    render_packet,
    review_packet,
)
from wiki_tool.review_state import REVIEW_STATE_RELATIVE_PATH, draft_fingerprint, short_fingerprint
from wiki_tool.safe_text import terminal_safe


def _short(draft: Path) -> str:
    return short_fingerprint(draft_fingerprint(draft))


def test_drafts_show_their_approval_state_through_each_change(
    good_vault: Path, make_draft: Any, approve: Any
) -> None:
    draft = make_draft("vuln-new-finding.md")

    entry = list_drafts(good_vault)[0]
    assert entry["draft"] == "proposed/vuln-new-finding.md"
    assert entry["approval"] == "pending"
    assert entry["target"] == "wiki/vulnerabilities/vuln-new-finding.md"
    assert entry["problems"] == []

    approve(good_vault, draft)
    assert list_drafts(good_vault)[0]["approval"] == "approved"

    draft.write_text(draft.read_text(encoding="utf-8") + "\nLate edit.\n", encoding="utf-8")
    assert list_drafts(good_vault)[0]["approval"] == "stale"


def test_rejected_draft_stays_in_place_and_apply_refuses_it(
    good_vault: Path, make_draft: Any
) -> None:
    draft = make_draft("vuln-new-finding.md")

    reject_draft(good_vault, draft, reviewer="Test Reviewer", reason="Root cause is wrong.")

    assert draft.exists()
    assert list_drafts(good_vault)[0]["approval"] == "rejected"
    with pytest.raises(DraftApplyError, match="was rejected by Test Reviewer"):
        apply_draft(good_vault, draft)
    assert draft.exists()
    assert not (good_vault / "wiki" / "vulnerabilities" / "vuln-new-finding.md").exists()


def test_approval_needs_the_current_short_hash(good_vault: Path, make_draft: Any) -> None:
    draft = make_draft("vuln-new-finding.md")

    with pytest.raises(DraftError, match="does not match"):
        approve_draft(
            good_vault,
            draft,
            reviewer="Test Reviewer",
            confirmation="000000000000",
        )
    assert list_drafts(good_vault)[0]["approval"] == "pending"


def test_approval_is_bound_to_the_bytes_that_were_reviewed(
    good_vault: Path, make_draft: Any
) -> None:
    draft = make_draft("vuln-new-finding.md")
    reviewed = _short(draft)
    draft.write_text(draft.read_text(encoding="utf-8") + "\nChanged later.\n", encoding="utf-8")

    with pytest.raises(DraftError, match="does not match"):
        approve_draft(good_vault, draft, reviewer="Test Reviewer", confirmation=reviewed)


def test_approval_refuses_a_draft_with_lint_problems(good_vault: Path, make_draft: Any) -> None:
    draft = make_draft("vuln-new-finding.md", body="Points at [[missing-note]].")

    with pytest.raises(DraftError, match="fix these problems before approving"):
        approve_draft(good_vault, draft, reviewer="Test Reviewer", confirmation=_short(draft))
    assert list_drafts(good_vault)[0]["approval"] == "pending"


def test_approval_records_the_reviewer_and_note(good_vault: Path, make_draft: Any) -> None:
    draft = make_draft("vuln-new-finding.md")

    result = approve_draft(
        good_vault,
        draft,
        reviewer="Ana\nForged: approved",
        note="  checked   the source  ",
        confirmation=_short(draft).upper(),
    )

    assert result["reviewer"] == "Ana Forged: approved"
    assert result["note"] == "checked the source"
    state = json.loads((good_vault / REVIEW_STATE_RELATIVE_PATH).read_text(encoding="utf-8"))
    assert state["drafts"]["vuln-new-finding.md"]["reviewer"] == "Ana Forged: approved"


def test_clean_single_line_rejects_empty_long_and_formatting_text() -> None:
    assert clean_single_line("  Ana   Lee ", "reviewer", 80, required=True) == "Ana Lee"
    with pytest.raises(DraftError, match="must not be empty"):
        clean_single_line("   ", "reviewer", 80, required=True)
    with pytest.raises(DraftError, match="at most 80"):
        clean_single_line("x" * 81, "reviewer", 80, required=True)
    with pytest.raises(DraftError, match="control or formatting"):
        clean_single_line("Eve\u202eRTL", "reviewer", 80, required=True)
    with pytest.raises(DraftError, match="control or formatting"):
        clean_single_line("Eve\x1b[2J", "reviewer", 80, required=True)


def test_terminal_output_escapes_control_and_bidi_characters() -> None:
    assert terminal_safe("ok\tline\nnext") == "ok\tline\nnext"
    assert terminal_safe("a\x1b[2Jb\u202ec") == "a\\u001b[2Jb\\u202ec"


def test_review_packet_carries_hashes_sources_and_status(good_vault: Path, make_draft: Any) -> None:
    draft = make_draft("vuln-new-finding.md")

    packet = review_packet(good_vault, draft)

    assert packet["sha256"] == draft_fingerprint(draft)
    assert packet["short_sha256"] == _short(draft)
    assert packet["approval"]["state"] == "pending"
    assert packet["target_exists"] is False
    assert packet["diff"] is None
    assert len(packet["sources"]) == 1
    source = packet["sources"][0]
    assert source["link"] == "[[raw/sources/source-2026-09-30-scan]]"
    assert source["path"] == "raw/sources/source-2026-09-30-scan.md"
    assert source["matches_manifest"] is True
    text = render_packet(packet)
    assert f"Confirm by typing the first 12 characters: {_short(draft)}" in text
    assert "Approval: pending: no decision recorded" in text


def test_review_packet_diffs_against_the_existing_note(good_vault: Path, make_draft: Any) -> None:
    draft = make_draft(
        "vuln-sql-injection.md",
        title="Replacement",
        finding_id="demo:replacement",
    )

    packet = review_packet(good_vault, draft)

    assert packet["target_exists"] is True
    assert packet["diff"] is not None
    assert '+title: "Replacement"' in packet["diff"].splitlines()
    assert '-title: "SQL injection in search endpoint"' in packet["diff"].splitlines()


def test_review_packet_warns_about_links_fixed_status_and_missing_finding(
    good_vault: Path, make_draft: Any
) -> None:
    make_draft("vuln-other.md", title="Other", finding_id="demo:other")
    draft = make_draft(
        "vuln-new-finding.md",
        body="Compare with [[proposed/vuln-other]].",
    )
    # Only the top-level status line changes; the history entry keeps `status: open`.
    draft.write_text(
        draft.read_text(encoding="utf-8")
        .replace("\nstatus: open\n", "\nstatus: fixed\n")
        .replace('\nfinding_id: "demo:new"\n', '\nfinding_id: ""\n'),
        encoding="utf-8",
    )

    warnings = review_packet(good_vault, draft)["warnings"]

    assert "links into proposed/: [[proposed/vuln-other]]" in warnings
    assert "status is fixed but status_history has no fixed entry" in warnings
    assert "vulnerability has no finding_id" in warnings


def test_review_packet_escapes_hostile_text_before_it_reaches_the_terminal(
    good_vault: Path, make_draft: Any
) -> None:
    draft = make_draft("vuln-new-finding.md", title="Harmless \u202e reversed")

    text = render_packet(review_packet(good_vault, draft))

    assert "\u202e" not in text
    assert "\\u202e" in text


def test_review_packet_describes_each_approval_state(good_vault: Path, make_draft: Any) -> None:
    draft = make_draft("vuln-new-finding.md")
    reject_draft(good_vault, draft, reviewer="Test Reviewer", reason="Revise it.")
    draft.write_text(draft.read_text(encoding="utf-8") + "\nRevised.\n", encoding="utf-8")

    packet = review_packet(good_vault, draft)

    assert packet["approval"]["state"] == "pending"
    assert "previously rejected by Test Reviewer" in render_packet(packet)


def test_cli_proposed_and_review_are_read_only(
    good_vault: Path, make_draft: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    draft = make_draft("vuln-new-finding.md")
    before = draft.read_bytes()

    assert main(["proposed", "--vault", str(good_vault), "--json"]) == 0
    listing = json.loads(capsys.readouterr().out)
    assert listing[0]["approval"] == "pending"

    assert main(["review", str(draft), "--vault", str(good_vault)]) == 0
    assert "Review packet: proposed/vuln-new-finding.md" in capsys.readouterr().out

    assert draft.read_bytes() == before
    assert not (good_vault / REVIEW_STATE_RELATIVE_PATH).exists()


def test_cli_approve_refuses_without_an_interactive_terminal(
    good_vault: Path,
    make_draft: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    draft = make_draft("vuln-new-finding.md")
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    monkeypatch.setattr(sys, "stdout", io.StringIO())

    code = main(["approve", str(draft), "--vault", str(good_vault), "--reviewer", "Test Reviewer"])

    assert code == 2
    assert "interactive terminal" in capsys.readouterr().err
    assert not (good_vault / REVIEW_STATE_RELATIVE_PATH).exists()


def test_is_interactive_is_false_for_pipes_and_broken_streams(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Pipe:
        def isatty(self) -> bool:
            return False

    class Broken:
        def isatty(self) -> bool:
            raise ValueError("I/O operation on closed file")

    monkeypatch.setattr(sys, "stdin", Pipe())
    monkeypatch.setattr(sys, "stdout", Pipe())
    assert _is_interactive() is False

    monkeypatch.setattr(sys, "stdin", Broken())
    assert _is_interactive() is False


def test_cli_approve_records_the_hash_a_person_types(
    good_vault: Path,
    make_draft: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    draft = make_draft("vuln-new-finding.md")
    monkeypatch.setattr("wiki_tool.cli._is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_args: _short(draft))

    code = main(["approve", str(draft), "--vault", str(good_vault), "--reviewer", "Test Reviewer"])

    assert code == 0
    assert list_drafts(good_vault)[0]["approval"] == "approved"
    captured = capsys.readouterr()
    assert "Review packet: proposed/vuln-new-finding.md" in captured.err
    assert "approved proposed/vuln-new-finding.md" in captured.out


@pytest.mark.parametrize("typed", ["not-the-hash", ""])
def test_cli_approve_cancels_on_a_wrong_or_empty_hash(
    good_vault: Path,
    make_draft: Any,
    monkeypatch: pytest.MonkeyPatch,
    typed: str,
) -> None:
    draft = make_draft("vuln-new-finding.md")
    monkeypatch.setattr("wiki_tool.cli._is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_args: typed)

    code = main(["approve", str(draft), "--vault", str(good_vault), "--reviewer", "Test Reviewer"])

    assert code == 2
    assert list_drafts(good_vault)[0]["approval"] == "pending"


def test_cli_approve_cancels_when_input_ends(
    good_vault: Path,
    make_draft: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    draft = make_draft("vuln-new-finding.md")
    monkeypatch.setattr("wiki_tool.cli._is_interactive", lambda: True)

    def _closed(*_args: object) -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", _closed)

    assert main(["approve", str(draft), "--vault", str(good_vault), "--reviewer", "T"]) == 2
    assert list_drafts(good_vault)[0]["approval"] == "pending"


def test_cli_reject_records_a_rejection(good_vault: Path, make_draft: Any) -> None:
    draft = make_draft("vuln-new-finding.md")

    code = main(
        [
            "reject",
            str(draft),
            "--vault",
            str(good_vault),
            "--reviewer",
            "Test Reviewer",
            "--reason",
            "Wrong severity.",
        ]
    )

    assert code == 0
    assert list_drafts(good_vault)[0]["approval"] == "rejected"


def test_cli_apply_needs_a_draft_or_all_approved(good_vault: Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["apply", "--vault", str(good_vault)])

    assert excinfo.value.code == 2


def test_list_drafts_reports_a_nested_draft_as_invalid(good_vault: Path) -> None:
    nested = good_vault / "proposed" / "archive"
    nested.mkdir()
    (nested / "vuln-old.md").write_text("---\ntype: vulnerability\n---\n", encoding="utf-8")

    entries = list_drafts(good_vault)

    assert entries[0]["approval"] == "invalid"
    assert "directly inside vault/proposed/" in entries[0]["problems"][0]


def test_list_drafts_sees_no_drafts_in_an_empty_proposed_folder(good_vault: Path) -> None:
    assert list_drafts(good_vault) == []
