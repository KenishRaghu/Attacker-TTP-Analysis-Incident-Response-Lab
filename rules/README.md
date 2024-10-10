# Detection rule engineering

This module exists only to support **emerging-threat-style detection** and ATT&CK-aligned coverage. Rules are **lab-tuned**; production deployments require tuning, staging, and false-positive review.

## Layout

| Path | Purpose |
|------|---------|
| `yara/malware_families.yar` | Malware family / stage strings (T1071, T1055, T1566) |
| `sigma/*.yml` | Windows process creation and DNS heuristics |
| `suricata/lab_emerging_threats.rules` | HTTP C2, ingress transfer, path traversal, phishing landing |
| `snort/lab_emerging_threats.rules` | Snort syntax parity for the same concepts |
| `zeek/*.zeek` | DNS length notice hook, HTTP stager URI notice |
| `feeds/emerging_threats_feed_sample.json` | Simulated IOC publish for pipeline tests |

## ATT&CK focus (as requested)

- **T1566** — Phishing (macro doc rule, IDS URI patterns, feed domains)
- **T1059.001** — PowerShell (`sigma/windows_powershell_suspicious.yml`, Python regex in `ttp_lab.detection_patterns`)
- **T1071** — C2 (Suricata/Snort HTTP, Zeek HTTP notice, YARA beacon strings)
- **T1003** — Credential dumping (`sigma/windows_credential_dumping.yml`, regex patterns)
- **T1055** — Process injection (`yara` loader rule, scenario 05 narrative)
- **T1105** — Ingress tool transfer (Sigma certutil/bits, Suricata/Snort downloader heuristic)

## Validation

- `pytest` loads all Sigma YAML files and checks IDS rule structure.
- When `yara` is installed, `tests/test_yara_rules.py` compiles rules against synthetic samples.

## Phishing IOC patterns and PowerShell regexes

Stable patterns live in `src/ttp_lab/detection_patterns.py` (`PHISHING_PATH_IOC`, `POWERSHELL_SUSPICIOUS`, DNS tunneling heuristic, credential dumping, macro indicators) so you can unit-test logic independently of vendor rule formats.
