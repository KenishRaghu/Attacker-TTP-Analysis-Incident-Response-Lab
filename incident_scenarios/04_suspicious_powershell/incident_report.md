# IR-2024-LAB-004: Suspicious PowerShell Execution

## Executive summary

EDR alerted on **encoded PowerShell** with **bypass execution policy** and **DownloadString** to an internal staging share mimic (lab). Activity consistent with **defense evasion** and potential follow-on payload execution.

---

## Alert timeline (UTC)

| Time | Source | Event |
|------|--------|-------|
| 2024-10-18T13:05Z | EDR | `powershell.exe -NoProfile -enc ...` |
| 2024-10-18T13:06Z | EDR | Child process `rundll32.exe` with unusual CLI |
| 2024-10-18T13:08Z | Proxy/DNS | Connection to rare domain (narrative) |

---

## Attacker objective

Execute in-memory payload and evade script block logging (narrative).

---

## TTP chain

1. **Execution**: PowerShell (T1059.001).
2. **Defense evasion**: Encoded command, hidden window (T1027).
3. **Ingress tool transfer**: Web download (T1105).

---

## MITRE ATT&CK mapping

| Stage | Technique | ID |
|-------|-----------|-----|
| Execution | PowerShell | T1059.001 |
| Command and Control | Ingress tool transfer | T1105 |

---

## Forensic artifact collection

| Artifact | Path |
|----------|------|
| Process tree | `forensic_artifacts/process_trees/powershell_attack_tree.json` |
| Command line log | `forensic_artifacts/notes/powershell_cmdline_sample.txt` |
| Memory | `forensic_artifacts/memory/volatility_pslist_excerpt.txt` (correlate PIDs) |

---

## IOC extraction

Extract command-line URLs and domains with `scripts/extract_iocs.py` against notes.

---

## Malware hash extraction

Downloader script hash optional; reflectively loaded DLL may leave **fileless** footprint — prioritize **memory image** and EDR telemetry.

---

## Suspicious process tree

See `powershell_attack_tree.json`.

---

## Network indicators (PCAP)

Secondary; primary is host telemetry. Optional PCAP merge if download over HTTP.

---

## Containment decision

| Priority | Action |
|----------|--------|
| P0 | Isolate host, capture memory if policy allows |
| P1 | Block IOC outbound |
| P1 | Hunt for same encoded prefix across fleet |

---

## Eradication checklist

- [ ] Kill malicious runspace processes
- [ ] Remove dropped files in `%TEMP%` (if any)
- [ ] Reset host or reimage if rootkit indicators

---

## Post-incident summary

Sigma rule `windows_powershell_suspicious.yml` provides SIEM coverage blueprint. Tune false positives with allowlists for admin tools.

---

## Inferred next steps

**Credential dumping** (scenario overlap), **lateral movement** via WMI/PsExec.

---

## New detection rule recommendation

- **Sigma**: already in `rules/sigma/windows_powershell_suspicious.yml`; add **parent process** constraint (`winword.exe` → `powershell.exe`) for phishing delivery linkage.
