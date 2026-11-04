from __future__ import annotations

import json
from pathlib import Path

import pytest

from wiki_tool.review_state import (
    REVIEW_STATE_RELATIVE_PATH,
    ReviewStateError,
    draft_fingerprint,
    draft_status,
    empty_state,
    load_review_state,
    record_applied,
    record_decision,
    require_approval,
    save_review_state,
    short_fingerprint,
)

HASH_A = "a" * 64
HASH_B = "b" * 64


def _approved_state(name: str = "vuln-x.md", fingerprint: str = HASH_A) -> dict:
    state = empty_state()
    record_decision(
        state,
        name,
        decision="approved",
        fingerprint=fingerprint,
        reviewer="Anthony",
        note="",
    )
    return state


def test_missing_state_file_is_an_empty_state(tmp_path: Path) -> None:
    assert load_review_state(tmp_path) == empty_state()


def test_state_round_trips_through_the_logs_folder(tmp_path: Path) -> None:
    state = _approved_state()

    save_review_state(tmp_path, state)

    assert (tmp_path / REVIEW_STATE_RELATIVE_PATH).exists()
    assert load_review_state(tmp_path) == state
    assert not (tmp_path / "logs" / "review-state.json.tmp").exists()


def test_invalid_json_is_reported_not_ignored(tmp_path: Path) -> None:
    path = tmp_path / REVIEW_STATE_RELATIVE_PATH
    path.parent.mkdir(parents=True)
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(ReviewStateError, match="invalid review state"):
        load_review_state(tmp_path)


@pytest.mark.parametrize(
    "payload",
    [
        {"version": 2, "drafts": {}, "events": []},
        {"version": 1, "drafts": [], "events": []},
        {"version": 1, "drafts": {"vuln-x.md": {"decision": "maybe"}}, "events": []},
        {
            "version": 1,
            "drafts": {
                "vuln-x.md": {
                    "decision": "approved",
                    "sha256": "not-a-digest",
                    "reviewer": "Anthony",
                    "note": "",
                }
            },
            "events": [],
        },
    ],
)
def test_malformed_state_is_rejected(tmp_path: Path, payload: dict) -> None:
    path = tmp_path / REVIEW_STATE_RELATIVE_PATH
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReviewStateError, match="malformed"):
        load_review_state(tmp_path)


def test_fingerprint_ignores_crlf_checkout_endings(tmp_path: Path) -> None:
    lf = tmp_path / "lf.md"
    crlf = tmp_path / "crlf.md"
    lf.write_bytes(b"---\ntype: vulnerability\n---\n\nBody line.\n")
    crlf.write_bytes(b"---\r\ntype: vulnerability\r\n---\r\n\r\nBody line.\r\n")

    assert draft_fingerprint(lf) == draft_fingerprint(crlf)
    assert len(short_fingerprint(draft_fingerprint(lf))) == 12


def test_draft_without_a_decision_is_pending() -> None:
    status, record = draft_status(empty_state(), "vuln-x.md", HASH_A)

    assert (status, record) == ("pending", None)


def test_approval_applies_only_to_the_approved_content() -> None:
    state = _approved_state(fingerprint=HASH_A)

    assert draft_status(state, "vuln-x.md", HASH_A)[0] == "approved"
    assert draft_status(state, "vuln-x.md", HASH_B)[0] == "stale"


def test_rejection_applies_only_to_the_rejected_content() -> None:
    state = empty_state()
    record_decision(
        state,
        "vuln-x.md",
        decision="rejected",
        fingerprint=HASH_A,
        reviewer="Anthony",
        note="Root cause is wrong.",
    )

    assert draft_status(state, "vuln-x.md", HASH_A)[0] == "rejected"
    # A revised draft has not been reviewed, so it is pending again.
    assert draft_status(state, "vuln-x.md", HASH_B)[0] == "pending"


def test_require_approval_explains_each_refusal() -> None:
    approved = _approved_state(fingerprint=HASH_A)
    assert require_approval(approved, "vuln-x.md", HASH_A)["reviewer"] == "Anthony"

    with pytest.raises(ReviewStateError, match="has no approval"):
        require_approval(empty_state(), "vuln-x.md", HASH_A)
    with pytest.raises(ReviewStateError, match="changed after it was approved"):
        require_approval(approved, "vuln-x.md", HASH_B)

    rejected = empty_state()
    record_decision(
        rejected,
        "vuln-x.md",
        decision="rejected",
        fingerprint=HASH_A,
        reviewer="Anthony",
        note="Wrong severity.",
    )
    with pytest.raises(ReviewStateError, match="was rejected by Anthony"):
        require_approval(rejected, "vuln-x.md", HASH_A)


def test_decisions_are_appended_to_the_event_trail() -> None:
    state = _approved_state()
    record_decision(
        state,
        "vuln-x.md",
        decision="rejected",
        fingerprint=HASH_B,
        reviewer="Anthony",
        note="Revise it.",
    )

    assert [event["action"] for event in state["events"]] == ["approved", "rejected"]
    assert state["drafts"]["vuln-x.md"]["decision"] == "rejected"


def test_unknown_decision_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="unknown decision"):
        record_decision(
            empty_state(),
            "vuln-x.md",
            decision="applied",
            fingerprint=HASH_A,
            reviewer="Anthony",
            note="",
        )


def test_applying_retires_the_active_decision_but_keeps_the_trail() -> None:
    state = _approved_state()

    record_applied(
        state,
        "vuln-x.md",
        fingerprint=HASH_A,
        target="wiki/vulnerabilities/vuln-x.md",
        approved_by="Anthony",
    )

    assert "vuln-x.md" not in state["drafts"]
    assert state["events"][-1]["action"] == "applied"
    assert state["events"][-1]["target"] == "wiki/vulnerabilities/vuln-x.md"
