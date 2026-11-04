"""Command-line entry point for SecVault's deterministic tooling."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import date
from pathlib import Path
from typing import Any

from .capture import PARSERS, capture_findings
from .operations import (
    DraftError,
    VaultError,
    apply_approved,
    apply_draft,
    audit_vault,
    build_catalog,
    find_uncovered_sources,
    lint_vault,
    query_catalog,
    update_manifest,
)
from .report import build_report, render_markdown
from .review import (
    NOTE_LIMIT,
    REVIEWER_LIMIT,
    approve_draft,
    clean_single_line,
    list_drafts,
    reject_draft,
    render_packet,
    review_packet,
)
from .review_state import SHORT_FINGERPRINT_LENGTH, ReviewStateError
from .safe_text import terminal_safe

COMMANDS = {
    "index": "Build the note catalog.",
    "manifest": "Record raw-source hashes.",
    "coverage": "Find raw sources without wiki coverage.",
    "lint": "Validate vault structure and integrity.",
    "query": "Search the note catalog.",
    "proposed": "List drafts in proposed/ with their review state.",
    "review": "Print the review packet for one draft.",
    "approve": "Record a human approval for one draft (interactive terminal only).",
    "reject": "Record a rejection; the draft stays in proposed/.",
    "apply": "Apply an approved draft from proposed/ to wiki/.",
    "audit": "Run the maintenance checks.",
    "capture": "Capture scanner findings as redacted raw evidence.",
    "report": "Summarize integrity, coverage, capture, and draft state.",
}


def _iso_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected a date in YYYY-MM-DD form") from exc


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line interface."""
    parser = argparse.ArgumentParser(
        prog="wiki-tool",
        description="Deterministic filesystem tooling for the SecVault vault.",
    )
    subparsers = parser.add_subparsers(dest="command")

    for name, help_text in COMMANDS.items():
        command_parser = subparsers.add_parser(name, help=help_text)
        command_parser.add_argument(
            "--vault",
            type=Path,
            default=Path("vault"),
            help="Path to the Obsidian-compatible vault (default: vault).",
        )
        command_parser.add_argument(
            "--json",
            action="store_true",
            help="Emit machine-readable JSON output.",
        )

        if name == "query":
            command_parser.add_argument("terms", nargs="+", help="Terms to search for.")
            command_parser.add_argument("--type", dest="note_type", help="Filter by note type.")
            command_parser.add_argument("--tag", help="Filter by exact tag.")
            command_parser.add_argument("--limit", type=int, default=10)
        elif name in {"review", "approve", "reject"}:
            command_parser.add_argument(
                "draft", type=Path, help="Draft file directly inside proposed/."
            )
            if name in {"approve", "reject"}:
                command_parser.add_argument(
                    "--reviewer", required=True, help="Name of the human reviewer."
                )
            if name == "approve":
                command_parser.add_argument("--note", default="", help="Optional one-line note.")
            if name == "reject":
                command_parser.add_argument(
                    "--reason",
                    required=True,
                    help="One-line reason. The draft stays in proposed/.",
                )
        elif name == "apply":
            command_parser.add_argument(
                "draft",
                type=Path,
                nargs="?",
                help="Approved draft directly inside proposed/.",
            )
            command_parser.add_argument(
                "--all-approved",
                action="store_true",
                help="Apply every approved draft in one batch with one lint pass.",
            )
            command_parser.add_argument(
                "--overwrite",
                action="store_true",
                help="Replace an existing wiki note whose status_history the draft extends.",
            )
        elif name == "capture":
            command_parser.add_argument(
                "--scanner",
                required=True,
                choices=sorted(PARSERS),
                help="Scanner that produced the report.",
            )
            command_parser.add_argument(
                "--input",
                required=True,
                type=Path,
                help="JSON report written by the scanner.",
            )
            command_parser.add_argument(
                "--path-prefix",
                help="Repository path the scan ran under, for example sample-app.",
            )
            command_parser.add_argument(
                "--date",
                type=_iso_date,
                help="Capture date in YYYY-MM-DD form (default: today, UTC).",
            )
            command_parser.add_argument(
                "--revision",
                help="Commit identifier recorded in each new raw note.",
            )

    return parser


def _print_lint(lint: dict[str, object]) -> None:
    if lint.get("ok"):
        print(f"lint: PASS (checked {lint.get('checked_notes', 0)} notes)")
        return
    print("lint: FAIL")
    for error in lint.get("errors", []):
        print(f"- {error}")


def _is_interactive() -> bool:
    """True only when a person is at the terminal. Agents, pipes, and test runners are not."""
    try:
        return bool(sys.stdin.isatty() and sys.stdout.isatty())
    except (AttributeError, ValueError):
        return False


def _approve_interactively(args: argparse.Namespace) -> dict[str, Any]:
    """Show the review packet, then approve only after a person types its short hash."""
    if not _is_interactive():
        raise DraftError(
            "approve needs an interactive terminal; a human must run it and type the hash"
        )
    clean_single_line(args.reviewer, "reviewer", REVIEWER_LIMIT, required=True)
    clean_single_line(args.note, "note", NOTE_LIMIT, required=False)
    packet = review_packet(args.vault, args.draft)
    print(render_packet(packet), end="", file=sys.stderr)
    print(
        f"Type the first {SHORT_FINGERPRINT_LENGTH} characters of the hash to approve, "
        "or press Enter to cancel: ",
        end="",
        file=sys.stderr,
        flush=True,
    )
    try:
        typed = input()
    except (EOFError, KeyboardInterrupt) as exc:
        raise DraftError("approval cancelled") from exc
    return approve_draft(
        args.vault,
        args.draft,
        reviewer=args.reviewer,
        note=args.note,
        confirmation=typed,
    )


def _text_result(command: str, result: object) -> None:
    if command == "lint" and isinstance(result, dict):
        if result.get("ok"):
            print(f"PASS: checked {result.get('checked_notes', 0)} notes")
        else:
            print("FAIL: vault lint found errors")
            for error in result.get("errors", []):
                print(f"- {error}")
        return
    if command == "query" and isinstance(result, list):
        for item in result:
            print(f"{item['score']:>3}  {item['path']}  {item['title']}")
        if not result:
            print("No matching notes.")
        return
    if command == "coverage" and isinstance(result, list):
        if result:
            print("\n".join(result))
        else:
            print("All raw sources have wiki coverage.")
        return
    if command == "capture" and isinstance(result, dict):
        print(
            f"captured {result['scanner']} ({result['findings']} findings): "
            f"{len(result['created'])} new, {result['known']} already captured, "
            f"{len(result['reopened'])} reopened, "
            f"{len(result['candidate_fixed'])} candidate_fixed"
        )
        for path in result["created"]:
            print(f"  + {terminal_safe(path)}")
        for finding_id in result["candidate_fixed"]:
            print(f"  ? {terminal_safe(finding_id)}: candidate for fixed; a human confirms it")
        _print_lint(result["lint"])
        return
    if command == "proposed" and isinstance(result, list):
        if not result:
            print("No drafts in proposed/.")
            return
        for entry in result:
            target = entry["target"] or "no applicable wiki target"
            print(terminal_safe(f"{entry['approval']:<9} {entry['draft']} -> {target}"))
            for problem in entry["problems"]:
                print(terminal_safe(f"          ! {problem}"))
        return
    if command == "approve" and isinstance(result, dict):
        print(
            terminal_safe(
                f"approved {result['draft']} as {result['reviewer']} "
                f"(sha256 {result['sha256'][:12]})"
            )
        )
        return
    if command == "reject" and isinstance(result, dict):
        print(
            terminal_safe(
                f"rejected {result['draft']} as {result['reviewer']}; "
                "the draft stays in proposed/ and apply will refuse it"
            )
        )
        return
    if command == "apply" and isinstance(result, dict):
        applied = result["applied"] if isinstance(result["applied"], list) else [result["applied"]]
        if not applied:
            print("No approved drafts to apply.")
            return
        for target in applied:
            print(f"  + {terminal_safe(str(target))}")
        if result["audit"]:
            print(f"audit: {result['audit']['status']}")
        return
    print(terminal_safe(json.dumps(result, indent=2, ensure_ascii=False, default=str)))


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, execute one deterministic operation, and report its result."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "apply" and bool(args.draft) == bool(args.all_approved):
        parser.error("apply needs exactly one of a draft path or --all-approved")

    try:
        if args.command == "index":
            result = build_catalog(args.vault)
        elif args.command == "manifest":
            result = update_manifest(args.vault)
        elif args.command == "coverage":
            result = find_uncovered_sources(args.vault)
        elif args.command == "lint":
            result = lint_vault(args.vault).as_dict()
        elif args.command == "query":
            result = query_catalog(
                args.vault,
                args.terms,
                note_type=args.note_type,
                tag=args.tag,
                limit=args.limit,
            )
        elif args.command == "proposed":
            result = list_drafts(args.vault)
        elif args.command == "review":
            result = review_packet(args.vault, args.draft)
        elif args.command == "approve":
            result = _approve_interactively(args)
        elif args.command == "reject":
            result = reject_draft(
                args.vault,
                args.draft,
                reviewer=args.reviewer,
                reason=args.reason,
            )
        elif args.command == "apply":
            if args.all_approved:
                result = apply_approved(args.vault)
            else:
                result = apply_draft(args.vault, args.draft, overwrite=args.overwrite)
        elif args.command == "capture":
            result = capture_findings(
                args.vault,
                args.scanner,
                args.input,
                path_prefix=args.path_prefix,
                captured_on=args.date,
                revision=args.revision,
            )
        elif args.command == "report":
            result = build_report(args.vault)
        else:
            result = audit_vault(args.vault)
    except (VaultError, ReviewStateError) as exc:
        print(f"wiki-tool: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(terminal_safe(json.dumps(result, indent=2, ensure_ascii=False, default=str)))
    elif args.command == "review":
        print(render_packet(result), end="")
    elif args.command == "report":
        print(terminal_safe(render_markdown(result)), end="")
    else:
        _text_result(args.command, result)

    if args.command == "lint" and isinstance(result, dict) and not result.get("ok"):
        return 1
    if args.command == "audit" and isinstance(result, dict) and result.get("status") != "passed":
        return 1
    if args.command == "apply" and isinstance(result, dict) and result.get("audit"):
        if result["audit"]["status"] != "passed":
            return 1
    if args.command == "capture" and isinstance(result, dict) and not result["lint"]["ok"]:
        return 1
    if args.command == "report" and isinstance(result, dict) and not result["ok"]:
        return 1
    if (
        args.command == "manifest"
        and isinstance(result, dict)
        and (result.get("changed") or result.get("removed"))
    ):
        print("wiki-tool: raw evidence was modified or removed", file=sys.stderr)
        return 1
    return 0
