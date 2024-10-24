from __future__ import annotations

from pathlib import Path

from ttp_lab.ioc_parser import extract_iocs_from_text

ROOT = Path(__file__).resolve().parents[1]


def test_extract_hashes_and_ips():
    text = """
    file sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    c2 203.0.113.50 and backup 198.51.100.10
    md5 d41d8cd98f00b204e9800998ecf8427e
    """
    b = extract_iocs_from_text(text)
    assert "d41d8cd98f00b204e9800998ecf8427e" in [x.lower() for x in b.md5]
    assert "203.0.113.50" in b.ipv4
    assert "198.51.100.10" in b.ipv4
    assert any(h.startswith("e3b0c442") for h in b.sha256)


def test_phishing_email_contains_domain():
    p = ROOT / "forensic_artifacts/email/phishing_sample_headers.txt"
    assert p.is_file()
    b = extract_iocs_from_text(p.read_text(encoding="utf-8"))
    assert any("enterprise-lab.example" in d for d in b.domains)
    assert any("@" in e for e in b.emails)
