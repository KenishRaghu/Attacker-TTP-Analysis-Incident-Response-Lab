# IR-2024-LAB-005: Malicious File Drop and Persistence

## Executive summary

Host executed a staged payload that **dropped a DLL** to disk, registered **Run key persistence**, and attempted **process injection** into a signed binary (lab narrative). Volatility and EDR timeline align on suspicious module load.

---

## Alert timeline (UTC)

| Time | Source | Event |
|------|--------|-------|
| 2024-10-19T01:10Z | EDR | New file `C:\\Users\\Public\\Updates\\svchost_helper.dll` |
| 2024-10-19T01:11Z | EDR | Registry value added under Run |
| 2024-10-19T01:13Z | EDR | `OpenProcess` + `WriteProcessMemory` chain |
| 2024-10-19T01:20Z | Memory triage | `malfind` / `ldrmodules` anomalies (see Volatility notes) |

---

## Attacker objective

Survive reboot and operate with **masquerading** binary context.

---

## TTP chain

1. **Ingress tool transfer**: Payload retrieved (T1105).
2. **Persistence**: Registry run keys (T1547.001).
3. **Privilege escalation / defense evasion**: Process injection primitives (T1055).

---

## MITRE ATT&CK mapping

| Stage | Technique | ID |
|-------|-----------|-----|
| Command and Control | Ingress tool transfer | T1105 |
| Persistence | Boot or logon | T1547.001 |
| Defense Evasion | Process injection | T1055 |

---

## Forensic artifact collection

| Artifact | Path |
|----------|------|
| Registry excerpt | `forensic_artifacts/registry/run_key_persistence_lab.reg` |
| Dropped file hash | Documented in `artifacts.json` |
| Process tree | `forensic_artifacts/process_trees/injection_tree.json` |
| Memory | `forensic_artifacts/memory/README.md` + `volatility_pslist_excerpt.txt` |
| YARA hunt | `rules/yara/malware_families.yar` — `Lab_C2_Loader_Dll` |

---

## IOC extraction

File path, registry key name, DLL export names (sandbox report overlap).

---

## Malware hash extraction

SHA256 in `artifacts.json` (lab placeholder aligns with feed sample).

---

## Suspicious process tree

`forensic_artifacts/process_trees/injection_tree.json`

---

## Network indicators (PCAP)

May correlate with scenario 02 if same intrusion; optional `c2_http_beacon_lab.pcap`.

---

## Containment decision

| Priority | Action |
|----------|--------|
| P0 | Isolate host |
| P0 | Block known bad hash network-wide |
| P1 | Registry autorun scan enterprise-wide for same value name |

---

## Eradication checklist

- [ ] Remove Run key value
- [ ] Delete dropped DLL + restore quarantine
- [ ] Reimage if kernel tampering suspected

---

## Post-incident summary

Combines **disk + registry + memory** evidence. Detection stack: **YARA** (loader), **Sigma** (unusual `regsvr32`/`rundll32` parents), **EDR** injection telemetry.

---

## Inferred next steps

Credential dumping, domain recon, data exfil staging.

---

## New detection rule recommendation

- **Sigma**: parent `explorer.exe` spawning `regsvr32.exe` with path in `Public` folder (high fidelity lab pattern — tune for your estate).
- **YARA**: `Lab_C2_Loader_Dll` with process memory acquisition.
