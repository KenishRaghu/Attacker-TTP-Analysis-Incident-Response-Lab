"""Reusable regex/heuristic patterns for detection engineering tests (lab-only)."""

from __future__ import annotations

import re

# Suspicious PowerShell (T1059.001) — high-signal lab patterns; tune in production.
POWERSHELL_SUSPICIOUS = re.compile(
    r"(?i)(-enc\s|[Bb]ypass|IEX\s*\(|Invoke-Expression|"
    r"DownloadString|FromBase64String|HiddenWindow|"
    r"-w\s+hIDDEN|Reflection\.Assembly)",
)

# DNS tunneling heuristic: long label or unusual TXT-heavy subdomains (simplified).
DNS_TUNNEL_LIKE = re.compile(
    r"(?i)^[a-z0-9.-]{60,}\.[a-z]{2,12}$",
)

# Credential dumping keywords (T1003) — process/command line context.
CRED_DUMP_PATTERNS = re.compile(
    r"(?i)(lsass\.exe.*procdump|procdump.*lsass|comsvcs\.dll,#24|sekurlsa::|"
    r"mimikatz|dump::sam|ntds\.dit)",
)

# Malicious macro indicators (VBA stream / script text).
MALICIOUS_MACRO = re.compile(
    r"(?i)(Auto_Open|Document_Open|Shell\s*\(|CreateObject\s*\(\s*\"WScript\.Shell\"|"
    r"GetObject\s*\(\s*\"winmgmts|powershell\.exe\s+-enc)",
)

# Phishing URL/path IOC patterns (landing pages).
PHISHING_PATH_IOC = re.compile(
    r"(?i)(/secure[_-]?login|/verify[_-]?account|/update[_-]?billing|"
    r"submit\?token=)",
)


def match_any(pattern: re.Pattern[str], text: str) -> bool:
    return bool(pattern.search(text))
