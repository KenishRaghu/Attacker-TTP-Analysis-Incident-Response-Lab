# IR-2024-LAB-003: Brute-Force Login Compromise

## Executive summary

Authentication logs show **high volume failed logins** from distributed IPs against a VPN appliance, followed by a **successful login** and new session from an unexpected country (synthetic UEBA).

---

## Alert timeline (UTC)

| Time | Source | Event |
|------|--------|-------|
| 2024-10-15T22:01Z | VPN / IdP | Spike in `authentication failure` from 40+ source IPs |
| 2024-10-15T23:44Z | VPN | First successful login for `svc_backup` after failure burst |
| 2024-10-15T23:50Z | Internal proxy | Rare internal scan from VPN pool IP |

---

## Attacker objective

Obtain valid VPN/IdP account through password guessing or password spray.

---

## TTP chain

1. **Recon** (external): Identify VPN gateway (T1595 — optional narrative).
2. **Credential access**: Brute force / password spray (T1110).
3. **Initial access**: Valid account use (T1078).

---

## MITRE ATT&CK mapping

| Stage | Technique | ID |
|-------|-----------|-----|
| Credential Access | Brute force | T1110 |
| Persistence / Access | Valid accounts | T1078 |

---

## Forensic artifact collection

| Artifact | Path |
|----------|------|
| Auth log excerpt | `forensic_artifacts/notes/auth_bruteforce_excerpt.log` |
| Correlation rules | Sigma patterns for thresholds (custom SIEM aggregation) |

---

## IOC extraction

Source IPs: see auth excerpt (synthetic `198.51.100.x` ranges). User: `svc_backup`.

---

## Malware hashes

None for pure cred brute-force path.

---

## Suspicious process tree

N/A on VPN concentrator; endpoint post-VPN: see `forensic_artifacts/process_trees/post_vpn_recon.json` if lateral movement enabled in exercise.

---

## Network indicators (PCAP)

Optional: not central to brute force (auth logs primary). PCAP module optional for blended attacks.

---

## Containment decision

| Priority | Action |
|----------|--------|
| P0 | Disable compromised account, force password reset |
| P1 | Enable geo-velocity / impossible travel for VPN |
| P1 | CAPTCHA / rate limits on VPN portal |

---

## Eradication checklist

- [ ] Review MFA enrollment for affected account
- [ ] Block top attacking ASNs at edge temporarily (careful with collateral)
- [ ] Audit `svc_*` account usage and least privilege

---

## Post-incident summary

Attack succeeded where **rate limiting and MFA gap** coexisted. Sigma-style rule: **count of failed auth per user > N from > M IPs in 1h** → auto step-up challenge.

---

## Inferred next steps

Internal **RDP** pivot, **credential dumping** on server (link to scenario 04/05), or **data staging**.

---

## New detection rule recommendation

- **SIEM**: sliding window aggregation on failed VPN auth + successful auth same user within 30 minutes.
- **Suricata** less relevant unless VPN is HTTP-based; prefer **IdP native analytics**.
