from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from wiki_tool.operations import update_manifest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def good_vault(tmp_path: Path) -> Path:
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURES / "good", vault)
    shutil.copytree(
        Path(__file__).parents[1] / "vault" / "schema",
        vault / "schema",
    )
    (vault / "proposed").mkdir()
    update_manifest(vault)
    return vault
