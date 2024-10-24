from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = ROOT / "rules/sigma"


def test_all_sigma_files_parse():
    files = sorted(SIGMA_DIR.glob("*.yml"))
    assert files, "expected sigma rules"
    for f in files:
        data = yaml.safe_load(f.read_text(encoding="utf-8"))
        assert data.get("title")
        assert "detection" in data
        assert "logsource" in data
