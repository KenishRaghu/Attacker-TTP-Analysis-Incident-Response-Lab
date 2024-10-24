from __future__ import annotations

from ttp_lab.detection_patterns import (
    CRED_DUMP_PATTERNS,
    DNS_TUNNEL_LIKE,
    MALICIOUS_MACRO,
    PHISHING_PATH_IOC,
    POWERSHELL_SUSPICIOUS,
    match_any,
)


def test_powershell_detection():
    assert match_any(POWERSHELL_SUSPICIOUS, "powershell -enc abc")
    assert match_any(POWERSHELL_SUSPICIOUS, "Invoke-Expression payload")
    assert not match_any(POWERSHELL_SUSPICIOUS, "powershell -File .\\install.ps1")


def test_cred_dump():
    assert match_any(CRED_DUMP_PATTERNS, "procdump -ma lsass.exe")
    assert match_any(CRED_DUMP_PATTERNS, "sekurlsa::logonpasswords")


def test_macro():
    assert match_any(MALICIOUS_MACRO, "Sub Auto_Open()\nShell(\"cmd\")")


def test_phish_path():
    assert match_any(PHISHING_PATH_IOC, "/secure-login-verify")


def test_dns_tunnel_heuristic():
    long_q = "a" * 65 + ".cc"
    assert match_any(DNS_TUNNEL_LIKE, long_q)
