# Security Policy

## Supported version

Only the latest released version in `CHANGELOG.md` is supported.

## Reporting a vulnerability

Report suspected vulnerabilities privately to `dev.epotala@gmail.com`. Include:

- the affected version;
- reproduction steps;
- security impact;
- any suggested mitigation.

Do not publish client scan files, authorization references, hostnames, or
evidence while reporting a tool vulnerability.

## Client-data handling

- Treat scan JSON, reports, and SHA-256 sidecars as confidential client data.
- Keep artifacts encrypted at rest and in transit.
- Do not store response bodies. The tool records response hashes and metadata.
- Delete artifacts according to the client contract and retention policy.
- Rotate or revoke access when an operator leaves the engagement.

## Safe operation

- Obtain written authorization before every scan.
- Use the exact authorized hostname and path.
- Keep TLS verification enabled except for explicitly approved test systems.
- Review every report before delivery.
- Stop a scan if the target behaves unexpectedly or availability degrades.
