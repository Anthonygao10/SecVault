"""Allow ``python -m wiki_tool`` to invoke the command-line interface."""

from wiki_tool.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
