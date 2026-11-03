from __future__ import annotations

from wiki_tool.redact import REDACTED, contains_secret, redact_text


def test_redacts_aws_style_keys_tokens_and_inline_assignments() -> None:
    token = "ghp_" + "x" * 36
    text = (
        "Key AKIAXXXXXXXXXXXXXXXX was found; "
        f"token {token} and password = 'correct-horse-battery-staple'"
    )

    redacted = redact_text(text)

    assert "AKIAXXXXXXXXXXXXXXXX" not in redacted
    assert token not in redacted
    assert "correct-horse-battery-staple" not in redacted
    assert REDACTED in redacted
    assert contains_secret(text)
    assert not contains_secret(redacted)


def test_redacts_private_key_blocks_completely() -> None:
    header = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    footer = "-----END " + "OPENSSH PRIVATE KEY-----"
    text = f"before {header}\nAAAAB3FAKEBODY\n{footer} after"

    redacted = redact_text(text)

    assert redacted == f"before {REDACTED} after"
    assert contains_secret(text)


def test_rule_names_and_plain_prose_are_not_redacted() -> None:
    text = "gitleaks:generic-api-key:sample-app/app.py:15 flagged; see aws-0086."

    assert redact_text(text) == text
    assert not contains_secret(text)
