from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_suricata_rules_have_alerts():
    p = ROOT / "rules/suricata/lab_emerging_threats.rules"
    lines = [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    assert any(ln.startswith("alert ") for ln in lines)
    assert all("sid:" in ln for ln in lines if ln.startswith("alert "))


def test_snort_rules_have_alerts():
    p = ROOT / "rules/snort/lab_emerging_threats.rules"
    lines = [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    assert any(ln.startswith("alert ") for ln in lines)


def test_emerging_feed_json():
    j = ROOT / "rules/feeds/emerging_threats_feed_sample.json"
    import json

    data = json.loads(j.read_text(encoding="utf-8"))
    assert data["feed_name"]
    assert len(data["iocs"]) >= 1
