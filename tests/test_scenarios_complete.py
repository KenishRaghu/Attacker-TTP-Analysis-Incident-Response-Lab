from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ROOT = ROOT / "incident_scenarios"


def test_each_scenario_has_report_and_artifacts():
    dirs = [p for p in SCENARIO_ROOT.iterdir() if p.is_dir() and p.name[0:2].isdigit()]
    assert len(dirs) == 6
    for d in sorted(dirs):
        report = d / "incident_report.md"
        art = d / "artifacts.json"
        assert report.is_file(), d
        assert art.is_file(), d
        data = json.loads(art.read_text(encoding="utf-8"))
        assert data.get("incident_id")
        assert data.get("mitre_primary")
