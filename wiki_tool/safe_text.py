"""Text cleaning for untrusted input such as scanner output, draft fields, and reviewer notes.

Two rules, applied where the text is written:

- Notes and raw evidence get one-line text with no control or bidirectional characters,
  so scanner output cannot start a Markdown heading, close a code span, or hide text.
- Terminal output shows those characters as escapes, so they cannot steer the display.
"""

from __future__ import annotations

import re

_CONTROL_OR_BIDI = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"
)


def strip_controls(text: str) -> str:
    """Replace control and bidirectional-override characters with spaces."""
    return _CONTROL_OR_BIDI.sub(" ", text)


def inline_text(value: object) -> str:
    """Flatten text to one line that is safe inside a Markdown code span or paragraph."""
    text = " ".join(strip_controls(str(value)).split())
    text = text.replace("`", "'")
    return text.replace("[[", "[ [").replace("]]", "] ]")


def terminal_safe(text: str) -> str:
    """Show control and bidirectional characters as escapes instead of sending them raw."""
    return _CONTROL_OR_BIDI.sub(lambda match: f"\\u{ord(match.group()):04x}", text)
