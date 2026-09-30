"""Command-line entry point for SecVault's deterministic tooling."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

COMMANDS = {
    "index": "Build the note catalog.",
    "manifest": "Record raw-source hashes.",
    "coverage": "Find raw sources without wiki coverage.",
    "lint": "Validate vault structure and integrity.",
    "query": "Search the note catalog.",
    "apply": "Apply an approved draft from proposed/.",
    "audit": "Run the maintenance checks.",
}


def build_parser() -> argparse.ArgumentParser:
    """Build the Phase 1 command surface without performing file operations."""
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
        elif name == "apply":
            command_parser.add_argument("draft", type=Path, help="Draft file to apply.")
            command_parser.add_argument(
                "--overwrite",
                action="store_true",
                help="Allow replacing an existing wiki note.",
            )

    return parser


def _stub_result(args: argparse.Namespace) -> dict[str, object]:
    """Return a stable placeholder until the Phase 3 implementations exist."""
    result: dict[str, object] = {
        "command": args.command,
        "status": "not_implemented",
        "vault": str(args.vault),
    }
    if hasattr(args, "terms"):
        result["terms"] = args.terms
    if hasattr(args, "draft"):
        result["draft"] = str(args.draft)
        result["overwrite"] = args.overwrite
    return result


def main(argv: Sequence[str] | None = None) -> int:
    """Parse a command and expose the complete Phase 1 command surface."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    result = _stub_result(args)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"wiki-tool: {args.command} is not implemented yet (scheduled for Phase 3).")
    return 0
