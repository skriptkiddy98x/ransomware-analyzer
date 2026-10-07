# Changelog

## v1.0.0
- Static analyzer: hashes, PE sections + entropy, import-based capability flags,
  string/IOC extraction, YARA matching.
- Behavioral observer: filesystem + entropy monitoring, mass-encryption / new-
  extension / ransom-note detection, process command-line flags.
- Correlation + reporting: MITRE ATT&CK mapping, scoring/verdict, heuristic family
  attribution, HTML + JSON reports.
- CLI (static / monitor / detonate / simulate) and a simple GUI.
- Benign self-test simulator for safe end-to-end validation.
- Unit + end-to-end tests.
