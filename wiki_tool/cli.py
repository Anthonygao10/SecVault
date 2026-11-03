"""Command-line entry point for SecVault's deterministic tooling."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import date
from pathlib import Path

from .capture import PARSERS, capture_findings
from .operations import (
    DraftApplyError,
    VaultError,
    apply_draft,
    audit_vault,
    build_catalog,
    find_uncovered_sources,
    lint_vault,
    query_catalog,
    update_manifest,
)
from .report import build_report, render_markdown

COMMANDS = {
    "index": "Build the note catalog.",
    "manifest": "Record raw-source hashes.",
    "coverage": "Find raw sources without wiki coverage.",
    "lint": "Validate vault structure and integrity.",
    "query": "Search the note catalog.",
    "apply": "Apply an approved draft from proposed/.",
    "audit": "Run the maintenance checks.",
    "capture": "Capture scanner findings as redacted raw evidence.",
    "report": "Summarize integrity, coverage, and capture state.",
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
        elif name == "apply":
            command_parser.add_argument("draft", type=Path, help="Draft file to apply.")
            command_parser.add_argument(
                "--overwrite",
                action="store_true",
                help="Allow replacing an existing wiki note.",
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
            print(f"  + {path}")
        for finding_id in result["candidate_fixed"]:
            print(f"  ? {finding_id}: candidate for fixed; a human confirms it")
        _print_lint(result["lint"])
        return
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, execute one deterministic operation, and report its result."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

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
        elif args.command == "apply":
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
    except (VaultError, DraftApplyError) as exc:
        print(f"wiki-tool: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    elif args.command == "report":
        print(render_markdown(result), end="")
    else:
        _text_result(args.command, result)

    if args.command == "lint" and isinstance(result, dict) and not result.get("ok"):
        return 1
    if args.command == "audit" and isinstance(result, dict) and result.get("status") != "passed":
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
