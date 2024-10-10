"""Extract IOCs from plain text (forensic notes, sandbox reports, email headers)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
DOMAIN_RE = re.compile(
    r"\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,63}))\b"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


@dataclass
class IOCBundle:
    md5: list[str] = field(default_factory=list)
    sha1: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)
    ipv4: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)

    def dedupe(self) -> None:
        for attr in ("md5", "sha1", "sha256", "ipv4", "domains", "emails"):
            vals: list[str] = getattr(self, attr)
            seen: set[str] = set()
            out: list[str] = []
            for v in vals:
                k = v.lower() if attr != "emails" else v
                if k not in seen:
                    seen.add(k)
                    out.append(v)
            setattr(self, attr, out)


def extract_iocs_from_text(text: str) -> IOCBundle:
    bundle = IOCBundle()
    lines = text.splitlines()
    for line in lines:
        bundle.md5.extend(MD5_RE.findall(line))
        bundle.sha1.extend(SHA1_RE.findall(line))
        bundle.sha256.extend(SHA256_RE.findall(line))
        bundle.ipv4.extend(IP_RE.findall(line))
        bundle.domains.extend(DOMAIN_RE.findall(line))
        bundle.emails.extend(EMAIL_RE.findall(line))
    bundle.dedupe()
    return bundle


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_iocs_from_paths(paths: Iterable[Path]) -> IOCBundle:
    merged = IOCBundle()
    for p in paths:
        if p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace")
            b = extract_iocs_from_text(text)
            merged.md5.extend(b.md5)
            merged.sha1.extend(b.sha1)
            merged.sha256.extend(b.sha256)
            merged.ipv4.extend(b.ipv4)
            merged.domains.extend(b.domains)
            merged.emails.extend(b.emails)
    merged.dedupe()
    return merged
