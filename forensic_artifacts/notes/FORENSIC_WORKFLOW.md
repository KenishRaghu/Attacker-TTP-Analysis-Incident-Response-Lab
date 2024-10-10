# Forensic workflow (lab)

This lab chains **open artifacts** to mirror a pragmatic IR sequence.

1. **Triage alerts** — map each scenario `incident_report.md` alert table to SIEM/EDR/IDS.
2. **Collect disk and memory** — memory README describes Volatility; disk artifacts include registry export and process trees.
3. **Network** — reproduce PCAPs with `python scripts/generate_sample_pcaps.py`, then analyze with **tshark**:

   ```bash
   tshark -r forensic_artifacts/pcaps/c2_http_beacon_lab.pcap -Y http -T fields -e http.host -e http.request.uri
   ```

4. **IOC extraction** — `python scripts/extract_iocs.py forensic_artifacts/notes/*.txt forensic_artifacts/email/*.txt --json`
5. **Email** — run header parser (`ttp_lab.phishing_header_analysis`) in tests / REPL for `Reply-To` vs `From` mismatch.
6. **Document** — every scenario ends with containment, eradication, and **new detection** recommendation to close the loop.

No real victim data is embedded; IOCs use documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`) where applicable.
