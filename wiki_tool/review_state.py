"""Review state: which drafts a human approved or rejected, and for which content.

The state lives in `logs/review-state.json`. An approval is bound to the SHA-256 of
the exact draft bytes it was given for. Editing the draft afterwards makes the
approval stale, and `apply` refuses it until a human approves the new content.

The file is plain JSON inside the vault, so this is a guardrail against agent
mistakes, not a tamper-proof record. The PRD threat model states that limit.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .hashing import sha256_file

REVIEW_STATE_RELATIVE_PATH = "logs/review-state.json"
DECISIONS = ("approved", "rejected")
FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}")
SHORT_FINGERPRINT_LENGTH = 12


class ReviewStateError(RuntimeError):
    """Raised when the review state file is unreadable or does not match its schema."""


def draft_fingerprint(path: Path) -> str:
    """Return the full digest that an approval is bound to."""
    return sha256_file(path)


def short_fingerprint(fingerprint: str) -> str:
    """Return the prefix a reviewer must type to approve a draft."""
    return fingerprint[:SHORT_FINGERPRINT_LENGTH]


def empty_state() -> dict[str, Any]:
    return {"version": 1, "drafts": {}, "events": []}


def load_review_state(root: Path) -> dict[str, Any]:
    """Load the review state, or an empty state for a vault with no decisions yet."""
    path = root / REVIEW_STATE_RELATIVE_PATH
    if not path.exists():
        return empty_state()
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReviewStateError(f"invalid review state: {REVIEW_STATE_RELATIVE_PATH}") from exc
    _validate(state)
    return state


def save_review_state(root: Path, state: dict[str, Any]) -> None:
    """Write the review state through a temporary file so an interruption cannot corrupt it."""
    path = root / REVIEW_STATE_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(state, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def draft_status(
    state: dict[str, Any], name: str, fingerprint: str
) -> tuple[str, dict[str, Any] | None]:
    """Return a draft's review state: pending, approved, stale, or rejected.

    A decision applies only to the content it was given for. A changed approval is
    stale. A changed rejection becomes pending again, because the revised draft has
    not been reviewed.
    """
    record = state["drafts"].get(name)
    if record is None:
        return "pending", None
    if record["sha256"] == fingerprint:
        return str(record["decision"]), record
    if record["decision"] == "approved":
        return "stale", record
    return "pending", record


def require_approval(state: dict[str, Any], name: str, fingerprint: str) -> dict[str, Any]:
    """Return the approval for this exact content, or explain why there is none."""
    status, record = draft_status(state, name, fingerprint)
    if status == "approved" and record is not None:
        return record
    if status == "rejected" and record is not None:
        raise ReviewStateError(
            f"{name} was rejected by {record['reviewer']} ({record['note']}); it cannot be applied"
        )
    if status == "stale":
        raise ReviewStateError(f"{name} changed after it was approved; approve it again")
    if record is not None:
        raise ReviewStateError(f"{name} changed after it was rejected; review it again")
    raise ReviewStateError(f"{name} has no approval; a human must review it and run `approve`")


def record_decision(
    state: dict[str, Any],
    name: str,
    *,
    decision: str,
    fingerprint: str,
    reviewer: str,
    note: str,
) -> None:
    """Set the active decision for a draft and append it to the event trail."""
    if decision not in DECISIONS:
        raise ValueError(f"unknown decision: {decision}")
    at = _now()
    state["drafts"][name] = {
        "decision": decision,
        "sha256": fingerprint,
        "reviewer": reviewer,
        "decided_at": at,
        "note": note,
    }
    state["events"].append(
        {
            "action": decision,
            "at": at,
            "draft": name,
            "sha256": fingerprint,
            "reviewer": reviewer,
            "note": note,
        }
    )


def record_applied(
    state: dict[str, Any], name: str, *, fingerprint: str, target: str, approved_by: str
) -> None:
    """Retire the decision for a draft that moved into wiki/, keeping it in the events."""
    state["drafts"].pop(name, None)
    state["events"].append(
        {
            "action": "applied",
            "at": _now(),
            "draft": name,
            "sha256": fingerprint,
            "approved_by": approved_by,
            "target": target,
        }
    )


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _malformed() -> ReviewStateError:
    return ReviewStateError(f"review state is malformed: {REVIEW_STATE_RELATIVE_PATH}")


def _validate(state: Any) -> None:
    if not isinstance(state, dict) or state.get("version") != 1:
        raise _malformed()
    drafts = state.get("drafts")
    events = state.get("events")
    if not isinstance(drafts, dict) or not isinstance(events, list):
        raise _malformed()
    for record in drafts.values():
        if not isinstance(record, dict) or record.get("decision") not in DECISIONS:
            raise _malformed()
        fingerprint = record.get("sha256")
        if not isinstance(fingerprint, str) or not FINGERPRINT_PATTERN.fullmatch(fingerprint):
            raise _malformed()
        if not isinstance(record.get("reviewer"), str) or not isinstance(record.get("note"), str):
            raise _malformed()
