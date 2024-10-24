from __future__ import annotations

from pathlib import Path

from ttp_lab.phishing_header_analysis import parse_simple_headers

ROOT = Path(__file__).resolve().parents[1]


def test_phishing_header_mismatch_signals():
    raw = (ROOT / "forensic_artifacts/email/phishing_sample_headers.txt").read_text(
        encoding="utf-8"
    )
    sig = parse_simple_headers(raw)
    assert sig.suspicious_mismatch is True
    assert sig.reply_to is not None
    assert len(sig.notes) >= 1
