"""Lightweight email header parsing for phishing IR (SPF/DKIM/DMARC signals)."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class HeaderSignals:
    return_path: str | None
    from_display: str | None
    reply_to: str | None
    received_hops: int
    authentication_results: str | None
    suspicious_mismatch: bool
    notes: list[str]


def parse_simple_headers(raw: str) -> HeaderSignals:
    """Parse a subset of headers stored as plain text in forensic samples."""
    lines = raw.replace("\r\n", "\n").split("\n")
    kv: dict[str, str] = {}
    cur = ""
    for line in lines:
        if not line.strip():
            continue
        if line.startswith((" ", "\t")) and cur:
            kv[cur] = kv.get(cur, "") + " " + line.strip()
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            cur = k.strip().lower()
            kv[cur] = v.strip()

    rp = kv.get("return-path")
    from_h = kv.get("from")
    rt = kv.get("reply-to") or kv.get("reply-to ")
    auth = kv.get("authentication-results") or kv.get("authentication-results")

    received = len(re.findall(r"^received:", raw, flags=re.I | re.M))

    notes: list[str] = []
    mismatch = False
    if rp and from_h:
        rp_email = _first_email(rp)
        from_email = _first_email(from_h)
        if rp_email and from_email and rp_email.lower() != from_email.lower():
            mismatch = True
            notes.append("Return-Path domain does not align with From address.")
    if rt:
        rt_em = _first_email(rt)
        from_em = _first_email(from_h or "")
        if rt_em and from_em and rt_em.lower() != from_em.lower():
            mismatch = True
            notes.append("Reply-To differs from From (common phishing signal).")
    if auth and "spf=fail" in auth.lower():
        notes.append("SPF fail in Authentication-Results.")
        mismatch = True
    if auth and "dkim=fail" in auth.lower():
        notes.append("DKIM fail in Authentication-Results.")

    return HeaderSignals(
        return_path=rp,
        from_display=from_h,
        reply_to=rt,
        received_hops=received,
        authentication_results=auth,
        suspicious_mismatch=mismatch,
        notes=notes,
    )


def _first_email(blob: str) -> str | None:
    m = re.search(r"<([^>]+)>", blob)
    if m:
        return m.group(1).strip()
    m2 = re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", blob)
    return m2.group(0) if m2 else None
