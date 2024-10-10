# IR-2024-LAB-001: Phishing → Credential Theft

## Executive summary

Synthetic incident: user received a spear-phishing email impersonating IT, clicked a credential-harvesting link, and submitted domain credentials. Session reuse was detected via impossible-travel and new MFA device registration anomalies (narrative).

---

## Alert timeline (UTC)

| Time | Source | Event |
|------|--------|-------|
| 2024-10-16T08:12Z | Email gateway | High phish score, URL rewrite bypass attempt |
| 2024-10-16T08:14Z | Proxy | HTTP GET to `secure-login-verify.example` |
| 2024-10-16T08:19Z | IdP | Successful login from unfamiliar ASN |
| 2024-10-16T08:22Z | IdP | MFA device added from same session |

---

## Attacker objective

Harvest corporate credentials and establish persistent IdP access.

---

## TTP chain (simple)

1. **Delivery**: Email with urgency and spoofed branding (T1566.002 Phishing: Spearphishing Link).
2. **Credential collection**: Clone portal collects password + MFA enrollment (T1556.006 — narrative follow-on; primary here is T1566).
3. **Initial access reuse**: Valid credentials used to authenticate (T1078).

---

## MITRE ATT&CK mapping

| Stage | Technique | ID |
|-------|-----------|-----|
| Initial Access | Phishing | T1566 |
| Credential Access | Phishing for credentials (link) | T1566.002 |
| Defense Evasion | User execution | T1204 |

---

## Forensic artifact collection

| Artifact | Location / method |
|----------|-------------------|
| Email headers | `forensic_artifacts/email/phishing_sample_headers.txt` |
| Proxy / edge logs | Correlation to PCAP `phishing_click_lab.pcap` |
| User agent | From HTTP log (see PCAP analysis) |
| IdP sign-in logs | UEBA / geo anomalies (simulated in narrative) |

---

## IOC extraction

See `artifacts.json`. Domains: `secure-login-verify.example`. Destination IP in PCAP: staging lab IP per capture metadata.

---

## Malware hash extraction

No binary payload delivered in this path; hashes **N/A** for primary story. Optional: document attachment hash if email had a `.html` drop (add in live exercise).

---

## Suspicious process tree

Browser-only user story; optional child process: `msedge.exe` → `rundll32.exe` if drive-by extended (not used in base lab).

Reference generic tree: `forensic_artifacts/process_trees/browser_phish_child.json`.

---

## Network indicators (PCAP)

- **PCAP**: `forensic_artifacts/pcaps/phishing_click_lab.pcap` (regenerate with `scripts/generate_sample_pcaps.py`).
- **Indicators**: HTTP GET to suspicious host, referer suggesting internal portal context.
- **tshark filter**: `http.host == "secure-login-verify.example"` (adjust if regenerated).

---

## Containment decision

| Priority | Action |
|----------|--------|
| P0 | Reset victim credentials, revoke active sessions, block IOC domains at resolver + proxy |
| P1 | Search enterprise mail for same campaign headers / URLs |
| P2 | Force step-up MFA for affected tenant |

---

## Eradication checklist

- [ ] Invalidate refresh tokens for affected user
- [ ] Remove rogue MFA device in IdP admin
- [ ] Block sender domain / URL at gateway
- [ ] Hunt for same `Reply-To` pattern across mailbox corpus

---

## Post-incident summary

Campaign used **credential phishing** rather than malware. Defensive improvements: **Sigma** (mail-rule simulation in SOC), **proxy blocklist** from IOC feed, user training on `Reply-To` mismatch. Recommended new detection: correlate **high phish score + successful IdP login within 15 minutes**.

---

## Inferred next steps (attacker)

Password spraying against VPN, internal spear-phish, or OAuth consent phishing if IdP allows app registration.

---

## New detection rule recommendation

- **Proxy/WAF**: block path patterns `/verify-account`, `/secure-login` on newly registered domains < 7 days.
- **Sigma / SIEM**: rule chaining `email.phishing.score > threshold` AND `web.proxy.request` to uncategorized domain within sliding window (implementation-specific).

---

## Volatility

Not applicable to primary narrative (no endpoint malware). Memory scenario deferred to scenarios 02/04/05.
