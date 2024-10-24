# Investigation walkthrough

Use this document as a **narrative spine** for interviews. Each step maps to concrete artifacts in the repo.

## How to work an incident end-to-end

1. **Ingest the alert** — Open the scenario `incident_report.md` and read the alert timeline. Decide whether the story is identity (phish/brute), endpoint (PowerShell/malware), or edge (web exploit).

2. **TTP identification** — For every row in the MITRE table in that scenario, be ready to explain *why* that technique applies and what evidence supports it.

3. **Collect artifacts** — Follow the “Forensic artifact collection” table: PCAP paths, JSON process trees under `forensic_artifacts/process_trees/`, registry sample, sandbox JSON, Volatility excerpt.

4. **Network proof** — Regenerate PCAPs if needed:
   ```bash
   PYTHONPATH=src python scripts/generate_sample_pcaps.py --out forensic_artifacts/pcaps
   ```
   Inspect with **tshark** (or Wireshark):
   ```bash
   tshark -r forensic_artifacts/pcaps/c2_http_beacon_lab.pcap -Y http -T fields -e http.host -e http.request.uri
   ```

5. **Extract IOCs** — Run the helper:
   ```bash
   PYTHONPATH=src python scripts/extract_iocs.py forensic_artifacts/notes/*.txt forensic_artifacts/email/*.txt --json
   ```

6. **Phishing forensics** — Parse `forensic_artifacts/email/phishing_sample_headers.txt`. Explain SPF/DKIM failures and `Reply-To` vs `From` divergence (implemented in `ttp_lab.phishing_header_analysis`).

7. **Containment / eradication** — Walk through the scenario checklist verbally. Tie each action to risk (credential replay, C2 continuity, persistence).

8. **Close the loop** — State one **new detection** you would ship (Sigma, Suricata, YARA, or Zeek) and which log source it needs.

## Scenario index

| Folder | One-liner you can defend |
|--------|---------------------------|
| `01_phishing_credential_theft` | Link + header mismatch → IdP session abuse |
| `02_malware_beaconing_c2` | DNS beacon + HTTP staging + sandbox confirmation |
| `03_brute_force_compromise` | Distributed failures → success; account disable priority |
| `04_suspicious_powershell` | Office → encoded PowerShell → LOLBin child |
| `05_malicious_drop_persistence` | Run key + DLL + injection narrative backed by memory triage |
| `06_web_exploit_attempt` | Traversal probes at the edge; WAF + IDS overlap |

Interview tip: end each scenario by stating **likely next attacker actions** and **your highest priority containment** (already present in each `incident_report.md`).
