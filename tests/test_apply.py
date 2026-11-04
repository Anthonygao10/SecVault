from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from wiki_tool.cli import main
from wiki_tool.operations import (
    DraftApplyError,
    DraftError,
    apply_approved,
    apply_draft,
    draft_name_problem,
    lint_vault,
)
from wiki_tool.review_state import (
    REVIEW_STATE_RELATIVE_PATH,
    draft_fingerprint,
    load_review_state,
    record_decision,
    save_review_state,
)

FIXTURES = Path(__file__).parent / "fixtures"
TARGET = "wiki/vulnerabilities/vuln-new-finding.md"

SOURCE_DRAFT = """---
type: source
title: "Manual source note"
tags:
  - source
  - infrastructure-as-code
created: 2026-11-03
updated: 2026-11-03
sources:
  - "[[raw/sources/source-2026-09-30-scan]]"
finding_id: "demo:source"
scanner: manual
captured: 2026-11-03
processed: false
---

# Manual source note
"""

LOG_DRAFT = """---
type: log
title: "Manual log"
tags:
  - log
created: 2026-11-03
updated: 2026-11-03
sources:
  - "[[raw/sources/source-2026-09-30-scan]]"
event: note
actor: agent
---

# Manual log
"""


def _history_draft(history: str, status: str = "fixed") -> str:
    return f"""---
type: vulnerability
title: "SQL injection in search endpoint"
tags:
  - vulnerability
  - cwe-89-sql-injection
  - owasp-a03-injection
  - input-validation
created: 2026-09-30
updated: 2026-11-03
sources:
  - "[[raw/sources/source-2026-09-30-scan]]"
severity: high
cwe: "CWE-89"
owasp: "A03:2021-Injection"
component: "sample-app/search.py"
status: {status}
status_history:
{history}
finding_id: "demo:sql-injection:search"
fix_commit: null
---

# SQL injection in search endpoint

Fixed with parameterized queries.
"""


ORIGINAL_HISTORY = """  - status: open
    date: 2026-09-30
    ref: "demo:sql-injection:search"
    note: "First recorded."
"""

EXTENDED_HISTORY = (
    ORIGINAL_HISTORY
    + """  - status: fixed
    date: 2026-11-03
    ref: "commit:abc123"
    note: "Parameterized the query."
"""
)

REWRITTEN_HISTORY = """  - status: fixed
    date: 2026-11-03
    ref: "commit:abc123"
    note: "History replaced instead of extended."
"""


def _add_broken_wiki_note(vault: Path) -> None:
    """Make the vault fail lint only once a draft has moved in, so the rollback runs."""
    target = vault / "wiki" / "concepts" / "concept-broken-link.md"
    target.write_bytes((FIXTURES / "bad" / "broken-link.md").read_bytes())


def _record_approval_without_lint(vault: Path, draft: Path) -> None:
    state = load_review_state(vault)
    record_decision(
        state,
        draft.name,
        decision="approved",
        fingerprint=draft_fingerprint(draft),
        reviewer="Test Reviewer",
        note="recorded without a lint check",
    )
    save_review_state(vault, state)


def test_apply_refuses_a_draft_without_approval(good_vault: Path, make_draft: Any) -> None:
    draft = make_draft("vuln-new-finding.md")

    with pytest.raises(DraftApplyError, match="has no approval"):
        apply_draft(good_vault, draft)

    assert draft.exists()
    assert not (good_vault / TARGET).exists()


def test_apply_refuses_a_draft_edited_after_approval(
    good_vault: Path, make_draft: Any, approve: Any
) -> None:
    draft = make_draft("vuln-new-finding.md")
    approve(good_vault, draft)
    draft.write_text(draft.read_text(encoding="utf-8") + "\nLate edit.\n", encoding="utf-8")

    with pytest.raises(DraftApplyError, match="changed after it was approved"):
        apply_draft(good_vault, draft)

    assert draft.exists()
    assert not (good_vault / TARGET).exists()


def test_apply_moves_an_approved_draft_and_records_the_decision(
    good_vault: Path, make_draft: Any, approve: Any
) -> None:
    draft = make_draft("vuln-new-finding.md")
    approve(good_vault, draft)

    result = apply_draft(good_vault, draft)

    assert result["applied"] == TARGET
    assert (good_vault / TARGET).exists()
    assert not draft.exists()
    assert result["audit"]["status"] == "passed"
    state = load_review_state(good_vault)
    assert state["drafts"] == {}
    assert [event["action"] for event in state["events"]] == ["approved", "applied"]
    applied = state["events"][-1]
    assert applied["target"] == TARGET
    assert applied["approved_by"] == "Test Reviewer"
    log = (good_vault / "logs" / "wiki-log.md").read_text(encoding="utf-8")
    assert f"applied vuln-new-finding.md to {TARGET}; approved_by=Test Reviewer" in log


def test_overwrite_requires_a_status_history_that_extends_the_existing_one(
    good_vault: Path, approve: Any
) -> None:
    existing = good_vault / "wiki" / "vulnerabilities" / "vuln-sql-injection.md"
    draft = good_vault / "proposed" / "vuln-sql-injection.md"

    draft.write_text(_history_draft(REWRITTEN_HISTORY), encoding="utf-8")
    approve(good_vault, draft)
    with pytest.raises(DraftApplyError, match="must extend the existing history"):
        apply_draft(good_vault, draft, overwrite=True)
    assert draft.exists()
    assert "First recorded." in existing.read_text(encoding="utf-8")

    draft.write_text(_history_draft(EXTENDED_HISTORY), encoding="utf-8")
    approve(good_vault, draft)
    apply_draft(good_vault, draft, overwrite=True)

    assert "Parameterized the query." in existing.read_text(encoding="utf-8")
    assert not draft.exists()


@pytest.mark.parametrize(
    "name",
    [
        "CON.md",
        "con.txt.md",
        "nul.md",
        "COM1.md",
        "LPT9.md",
        "vuln-x.md:stream",
        "vuln-x.md.",
        "vuln-x.md ",
        "vuln-x",
        ".hidden.md",
        "vuln/x.md",
        "..md",
        "vuln-x.MD",
    ],
)
def test_unsafe_draft_names_are_refused(name: str) -> None:
    assert draft_name_problem(name) is not None


def test_ordinary_draft_names_are_accepted() -> None:
    assert draft_name_problem("vuln-new-finding.md") is None
    assert draft_name_problem("console-notes.md") is None


def test_drafts_outside_proposed_are_refused(good_vault: Path) -> None:
    outside = good_vault.parent / "outside" / "vuln-outside.md"
    outside.parent.mkdir()
    outside.write_text(_history_draft(ORIGINAL_HISTORY), encoding="utf-8")
    wiki_note = good_vault / "wiki" / "vulnerabilities" / "vuln-sql-injection.md"
    escape = good_vault / "proposed" / ".." / "wiki" / "vulnerabilities" / "vuln-sql-injection.md"

    for candidate in (outside, wiki_note, escape):
        with pytest.raises(DraftError, match="directly inside vault/proposed/"):
            apply_draft(good_vault, candidate)

    assert outside.exists()
    assert wiki_note.exists()


def test_symlinked_drafts_are_refused(good_vault: Path, make_draft: Any, approve: Any) -> None:
    real = make_draft("vuln-real.md")
    approve(good_vault, real)
    link = good_vault / "proposed" / "vuln-link.md"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("creating symbolic links needs extra privileges on this platform")

    with pytest.raises(DraftError, match="symbolic link"):
        apply_draft(good_vault, link)
    assert real.exists()


@pytest.mark.parametrize(
    ("name", "text"),
    [("source-2026-11-03-manual-note.md", SOURCE_DRAFT), ("log-2026-11-03-manual.md", LOG_DRAFT)],
)
def test_source_and_log_drafts_are_not_applicable(
    good_vault: Path, approve: Any, name: str, text: str
) -> None:
    draft = good_vault / "proposed" / name
    draft.write_text(text, encoding="utf-8")
    assert lint_vault(good_vault).ok, lint_vault(good_vault).errors
    approve(good_vault, draft)

    with pytest.raises(DraftApplyError, match="not an applicable wiki type"):
        apply_draft(good_vault, draft)
    assert draft.exists()


def test_nested_drafts_fail_lint_and_cannot_be_applied(good_vault: Path, make_draft: Any) -> None:
    nested = make_draft("vuln-old.md", folder="proposed/archive")

    assert any(
        "drafts must sit directly in proposed/" in error for error in lint_vault(good_vault).errors
    )
    with pytest.raises(DraftError, match="directly inside vault/proposed/"):
        apply_draft(good_vault, nested)
    assert nested.exists()


def test_malformed_review_state_blocks_apply_and_fails_lint(
    good_vault: Path, make_draft: Any
) -> None:
    draft = make_draft("vuln-new-finding.md")
    state_path = good_vault / REVIEW_STATE_RELATIVE_PATH
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text("{not json", encoding="utf-8")

    assert any("invalid review state" in error for error in lint_vault(good_vault).errors)
    with pytest.raises(DraftApplyError, match="invalid review state"):
        apply_draft(good_vault, draft)
    assert draft.exists()


def test_lint_failure_after_the_move_restores_the_draft(
    good_vault: Path, make_draft: Any, approve: Any
) -> None:
    _add_broken_wiki_note(good_vault)
    draft = make_draft("vuln-new-finding.md")
    before = draft.read_bytes()
    approve(good_vault, draft)

    with pytest.raises(DraftApplyError, match="failed lint after apply"):
        apply_draft(good_vault, draft)

    assert draft.read_bytes() == before
    assert not (good_vault / TARGET).exists()
    state = load_review_state(good_vault)
    assert state["drafts"]["vuln-new-finding.md"]["decision"] == "approved"
    assert all(event["action"] != "applied" for event in state["events"])


def test_batch_apply_moves_every_approved_draft_and_skips_the_rest(
    good_vault: Path, make_draft: Any, approve: Any
) -> None:
    first = make_draft("vuln-first-finding.md", title="First", finding_id="demo:first")
    second = make_draft("vuln-second-finding.md", title="Second", finding_id="demo:second")
    unapproved = make_draft("vuln-third-finding.md", title="Third", finding_id="demo:third")
    approve(good_vault, first)
    approve(good_vault, second)

    result = apply_approved(good_vault)

    assert result["applied"] == [
        "wiki/vulnerabilities/vuln-first-finding.md",
        "wiki/vulnerabilities/vuln-second-finding.md",
    ]
    assert result["audit"]["status"] == "passed"
    assert not first.exists() and not second.exists()
    assert unapproved.exists()
    state = load_review_state(good_vault)
    assert [event["action"] for event in state["events"]] == [
        "approved",
        "approved",
        "applied",
        "applied",
    ]


def test_batch_apply_with_nothing_approved_changes_nothing(
    good_vault: Path, make_draft: Any
) -> None:
    draft = make_draft("vuln-new-finding.md")

    assert apply_approved(good_vault) == {"applied": [], "audit": None}
    assert draft.exists()


def test_batch_apply_never_overwrites_an_existing_note(
    good_vault: Path, make_draft: Any, approve: Any
) -> None:
    draft = make_draft("vuln-sql-injection.md", title="Replacement", finding_id="demo:new")
    approve(good_vault, draft)
    existing = good_vault / "wiki" / "vulnerabilities" / "vuln-sql-injection.md"
    before = existing.read_bytes()

    with pytest.raises(DraftApplyError, match="refusing to overwrite"):
        apply_approved(good_vault)

    assert draft.exists()
    assert existing.read_bytes() == before


def test_batch_apply_stops_before_moving_when_an_approved_draft_is_invalid(
    good_vault: Path, make_draft: Any, approve: Any
) -> None:
    good = make_draft("vuln-good-finding.md", title="Good", finding_id="demo:good")
    broken = make_draft(
        "vuln-broken-finding.md",
        title="Broken",
        finding_id="demo:broken",
        body="Points at [[missing-note]].",
    )
    approve(good_vault, good)
    _record_approval_without_lint(good_vault, broken)

    with pytest.raises(DraftApplyError, match="cannot apply invalid draft"):
        apply_approved(good_vault)

    assert good.exists() and broken.exists()
    assert not (good_vault / "wiki" / "vulnerabilities" / "vuln-good-finding.md").exists()


def test_batch_lint_failure_rolls_back_every_move(
    good_vault: Path, make_draft: Any, approve: Any
) -> None:
    _add_broken_wiki_note(good_vault)
    first = make_draft("vuln-first-finding.md", title="First", finding_id="demo:first")
    second = make_draft("vuln-second-finding.md", title="Second", finding_id="demo:second")
    first_bytes, second_bytes = first.read_bytes(), second.read_bytes()
    approve(good_vault, first)
    approve(good_vault, second)

    with pytest.raises(DraftApplyError, match="failed lint after apply"):
        apply_approved(good_vault)

    assert first.read_bytes() == first_bytes
    assert second.read_bytes() == second_bytes
    assert not (good_vault / "wiki" / "vulnerabilities" / "vuln-first-finding.md").exists()
    assert not (good_vault / "wiki" / "vulnerabilities" / "vuln-second-finding.md").exists()
    state = load_review_state(good_vault)
    assert set(state["drafts"]) == {"vuln-first-finding.md", "vuln-second-finding.md"}


def test_cli_apply_reports_the_target_and_the_audit(
    good_vault: Path, make_draft: Any, approve: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    draft = make_draft("vuln-new-finding.md")
    approve(good_vault, draft)

    assert main(["apply", str(draft), "--vault", str(good_vault)]) == 0

    output = capsys.readouterr().out
    assert f"+ {TARGET}" in output
    assert "audit: passed" in output


def test_cli_batch_apply_with_nothing_approved_is_a_quiet_success(
    good_vault: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["apply", "--all-approved", "--vault", str(good_vault)]) == 0
    assert "No approved drafts to apply." in capsys.readouterr().out
