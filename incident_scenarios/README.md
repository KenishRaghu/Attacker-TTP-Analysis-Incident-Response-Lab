# Incident Response Simulation Lab

Each folder is a **closed synthetic incident** aligned to MITRE ATT&CK. Artifacts under `forensic_artifacts/` are labeled as lab-generated; PCAPs can be reproduced with `scripts/generate_sample_pcaps.py`.

## Scenarios

| ID | Scenario | Primary ATT&CK |
|----|----------|----------------|
| 01 | Phishing → credential theft | T1566 |
| 02 | Malware beaconing / C2 | T1071 |
| 03 | Brute-force account compromise | T1110 |
| 04 | Suspicious PowerShell | T1059.001 |
| 05 | Malicious drop + persistence | T1105, T1547 |
| 06 | Public web exploit attempt | T1190 |

For each scenario open `incident_report.md` for the investigation walkthrough, containment, and recommended new detection content.
