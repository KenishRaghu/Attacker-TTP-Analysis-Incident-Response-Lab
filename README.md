# Attacker TTP Analysis & Incident Response Lab

Professional portfolio project focused on **two capabilities only**:

1. **Incident Response Simulation Lab** — Synthetic incidents with TTP analysis, MITRE mapping, forensic artifacts, PCAP-backed network indicators, containment, eradication, and post-incident detection recommendations.
2. **Detection Rule Engineering** — YARA, Sigma, Suricata, Snort, Zeek, IOC feed simulation, and Python-testable detection patterns (PowerShell, phishing paths, DNS tunneling heuristics, credential dumping, macros).

Stack: **Python**, **YARA**, **Sigma**, **Suricata/Snort**, **Zeek scripts**, **synthetic Zeek/PCAP-friendly traffic**, **Volatility-oriented workflow** (sample outputs; no multi-GB dump shipped), **Wireshark/tshark PCAP samples**, **Docker**, **pytest**, **GitHub Actions**.

> **Defensibility:** All IOCs use [TEST-NET / documentation ranges](https://datatracker.ietf.org/doc/html/rfc5737) and `.example` hostnames where possible. PCAPs are generated locally with `scripts/generate_sample_pcaps.py` (Scapy). This is a **lab**, not live intrusion data.

---

## Repository map

| Path | Purpose |
|------|---------|
| `incident_scenarios/` | Six full incident write-ups (`incident_report.md` + `artifacts.json`) |
| `forensic_artifacts/` | PCAPs, email headers, process trees, registry sample, sandbox JSON, Volatility excerpt, notes |
| `rules/` | YARA, Sigma, Suricata, Snort, Zeek, IOC feed sample — see `rules/README.md` |
| `src/ttp_lab/` | IOC parser, phishing header helper, shared detection regex/heuristics |
| `scripts/` | PCAP generator, IOC extraction CLI |
| `tests/` | pytest validation (Sigma YAML, IDS text, IOC logic, optional YARA CLI) |
| `INVESTIGATION_WALKTHROUGH.md` | Interview-oriented investigation spine |

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src python scripts/generate_sample_pcaps.py --out forensic_artifacts/pcaps
PYTHONPATH=src pytest -q
```

**Docker** (runs pytest in a slim image with YARA installed):

```bash
docker compose build && docker compose run --rm lab-tests
```

**Optional:** install system `yara` so `tests/test_yara_rules.py` is not skipped.

---

## MITRE ATT&CK coverage (lab scenarios + rules)

| Scenario / rule set | Notable techniques | Evidence in repo |
|--------------------|--------------------|------------------|
| Phishing credential theft | T1566, T1566.002 | `01_*`, email headers, `phishing_click_lab.pcap` |
| Malware beacon / C2 | T1071.001, T1071.004, T1105 | `02_*`, PCAPs, Suricata/Snort, Zeek, YARA |
| Brute-force compromise | T1110, T1078 | `03_*`, `auth_bruteforce_excerpt.log` |
| Suspicious PowerShell | T1059.001, T1105 | `04_*`, Sigma + `detection_patterns.py` |
| Malicious drop + persistence | T1105, T1547.001, T1055 | `05_*`, registry, process tree, YARA loader |
| Web exploit attempt | T1190 | `06_*`, traversal PCAP, IDS rules |
| Cross-cutting detection | T1003 | Sigma + regex for credential dumping |

---

## Forensics workflow (realistic, lab-scoped)

Documented in `forensic_artifacts/notes/FORENSIC_WORKFLOW.md`:

- PCAP analysis with **tshark** / Wireshark  
- **Volatility 3** plugin examples and synthetic `volatility_pslist_excerpt.txt`  
- **IOC parser** for notes and sandbox-style reports  
- Email **header** feature extraction for phishing (`ttp_lab.phishing_header_analysis`)

Full Windows memory images are intentionally excluded; the README under `forensic_artifacts/memory/` describes acquisition and analysis expectations.

---

## Investigation walkthrough

See **`INVESTIGATION_WALKTHROUGH.md`** for a scenario-by-scenario explanation path suitable for hiring conversations.

---

## GitHub repository name

The reference implementation is pushed to **`KenishRaghu/Attacker-TTP-Analysis-Incident-Response-Lab`**. If you want the shorter slug **`attacker-ttp-analysis-ir-lab`**, rename the repository in GitHub **Settings → General → Repository name** (GitHub preserves redirects from the old name for a period).
