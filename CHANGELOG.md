# Changelog

## Unreleased

- Adopted the product name **ePotala Security Toolkit**, shortened to
  **EPX Toolkit**, with the component names EPX Recon, EPX Forensics,
  EPX Report, and EPX Verify. Existing command names remain unchanged.
- Added offline incident-evidence analysis with bounded support for gzip, zip,
  tar, and tar.gz containers, access-log correlation, static PHP/configuration
  classification, conservative SQL injection checks, evidence hashing, incident
  timelines, indicators, and standalone Markdown/HTML incident reports.
- Added a curated MITRE ATT&CK technique mapping to findings, schema validation
  for the mapping, and an ATT&CK coverage section in the Markdown and HTML
  reports. The mapping is a hand-curated reference (weakness-to-technique), not
  evidence that any technique was attempted.
- Added opt-in CVE correlation (`--cve-source wpscan`, off by default). It sends
  detected component slugs/versions to the WPScan feed, so it warns that client
  inventory leaves the engagement boundary and requires an API key. Matches are
  capped at "Medium" confidence (the reported version is unverified), mapped to
  ATT&CK T1190, and a feed failure degrades to a recorded error, not a crash.

## 1.0.0 - 2026-06-14

- Added versioned scan schema `1.0`.
- Added scan UUIDs, authorization references, scope, settings, and status.
- Added per-check completion records and deterministic finding IDs.
- Added confidence, category, and supporting request IDs to findings.
- Added rate limiting, request budgets, response limits, redirect scope, and
  HTTPS downgrade protection.
- Added hash-only HTTP evidence records with status, timing, content type, and
  response SHA-256.
- Added atomic private artifact writes and SHA-256 sidecars.
- Added standalone `epx-verify`.
- Added report integrity verification and analyst review status.
- Added HTTPS-enforcement and browser-security-header checks.
- Expanded the automated test suite.

## 0.2.0 - 2026-06-14

- Corrected false-positive and overclaiming behavior.
- Added response limits, redirect hostname controls, schema validation, and
  beginner-friendly error handling.
- Added active SVG script-content inspection.

## 0.1.0 - 2026-06-14

- Initial read-only WordPress reconnaissance and reporting prototype.
