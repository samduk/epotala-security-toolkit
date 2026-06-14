# ePotala Security Toolkit

**Short name:** EPX Toolkit

**Tagline:** Authorized assessment, forensic analysis, and evidence-driven reporting.

The ePotala Security Toolkit is a dependency-free suite for authorized
WordPress and WooCommerce security assessments and offline incident-evidence
analysis.

This document is the operating procedure for analysts. Follow the applicable
workflow from preparation through delivery. Do not skip authorization,
integrity verification, or analyst review.

## Contents

- [Programs](#programs)
- [Mandatory Operating Rules](#mandatory-operating-rules)
- [Installation](#installation)
- [Case Preparation](#case-preparation)
- [Workflow A: External Website Assessment](#workflow-a-external-website-assessment)
- [External Assessment Controls](#external-assessment-controls)
- [Optional CVE Correlation](#optional-cve-correlation)
- [Workflow B: Incident Evidence Analysis](#workflow-b-incident-evidence-analysis)
- [Command Reference](#command-reference)
- [Exit Codes](#exit-codes)
- [Troubleshooting](#troubleshooting)
- [Data Handling](#data-handling)
- [Final Operator Checklist](#final-operator-checklist)

## Programs

| Program | Purpose | Network activity |
|---|---|---|
| **EPX Recon** (`epx-recon`) | Run an external, read-only website assessment | Yes, against the authorized target |
| **EPX Forensics** (`epx-forensics`) | Analyze supplied logs, archives, PHP files, configuration, and SQL | No |
| **EPX Report** (`epx-report`) | Convert a scan or forensic JSON artifact into Markdown or HTML | No |
| **EPX Verify** (`epx-verify`) | Verify an artifact's SHA-256 sidecar and validate JSON schemas | No |

Choose one collection workflow:

- **External assessment:** start with `epx-recon`.
- **Incident evidence:** start with `epx-forensics`.

Both workflows then use `epx-verify` and `epx-report`.

## Mandatory Operating Rules

1. Obtain written authorization before scanning or handling client evidence.
2. Use the exact hostname, path, and testing window stated in the authorization.
3. Create a unique case or engagement identifier before starting.
4. Keep client evidence and generated artifacts confidential.
5. Verify every JSON artifact before generating a report.
6. Review every finding manually before using `--reviewed-by`.
7. Verify the final report before delivery.
8. Keep each artifact with its matching `.sha256` sidecar.
9. Never execute suspicious PHP, scripts, or binaries supplied as evidence.
10. Stop testing if the target becomes unstable or the approved scope is unclear.

## Requirements

- Linux or another environment capable of running Python 3.10 or newer
- Python standard library
- Written authorization, SOW, ticket, or evidence-transfer reference
- A case-specific folder with restricted access

The core toolkit has no third-party Python dependencies. Development checks
also use `mypy` and `pylint` when running `make check`.

## Installation

### Option A: Run from the source folder

Open a terminal and enter the tool directory:

```bash
cd /path/to/epotala/tool
```

Make the commands executable:

```bash
chmod +x epx-recon epx-forensics epx-report epx-verify
```

Confirm the installed version:

```bash
./epx-recon --version
./epx-forensics --version
./epx-report --version
./epx-verify --version
```

### Option B: Install in a virtual environment

```bash
cd /path/to/epotala/tool
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

After installation, the commands can be run without `./`:

```bash
epx-recon --version
epx-forensics --version
epx-report --version
epx-verify --version
```

The examples below use the source-folder form, such as `./epx-recon`.

## Command Formatting

A backslash (`\`) at the end of a shell line means that the command continues
on the next line. Press Enter after each line.

Do not type HTML such as `<br>`, `<br/>`, or `\<br/>` into the terminal.

Use quotation marks around names and references containing spaces:

```bash
--operator "Analyst Name"
--client "Client Organization"
```

## Case Preparation

Record these values before running a command:

| Field | Example |
|---|---|
| Case or report ID | `EPX-CLIENT-2026-014` |
| Authorization reference | `SOW-2026-014` |
| Client | `Client Organization` |
| Operator | `Analyst Name` |
| Authorized target | `https://client.example` |
| Authorized window | `2026-06-15 09:00-12:00 UTC` |
| Approved CVE data sharing | `Yes` or `No` |
| Retention requirement | `Delete 30 days after delivery` |

Use predictable output names:

```text
reports/EPX-CLIENT-2026-014-scan.json
reports/EPX-CLIENT-2026-014-report.md
reports/EPX-CLIENT-2026-014-report.html
```

Restrict the shell session and create the report folder:

```bash
umask 077
mkdir -p reports
```

The tool also writes generated artifacts and sidecars with owner-only
permissions (`0600`).

## Workflow A: External Website Assessment

Use this workflow for an authorized, external, read-only WordPress or
WooCommerce assessment.

### A1. Confirm Scope

Confirm all of the following:

- the hostname and optional WordPress subfolder are authorized;
- the scheme is correct: `https://` or `http://`;
- the testing window is active;
- the operator has the authorization reference available;
- any third-party CVE lookup is separately approved.

Valid target examples:

```text
https://client.example
https://client.example/wordpress
http://local-client.htb
```

Do not pass:

- an administration page such as `/wp-admin/`;
- an individual post URL;
- a query string;
- an IP address or hostname outside the written scope.

### A2. Check the Tool

```bash
./epx-recon --version
./epx-recon --list-checks
```

The current checks are:

| Check ID | Purpose |
|---|---|
| `server-banner` | Detect exact web-server version disclosure |
| `wp-version` | Inventory publicly reported WordPress versions |
| `components` | Inventory public plugin and theme references |
| `user-enum` | Record public author names and slugs |
| `xmlrpc` | Identify risky XML-RPC methods |
| `exposed-files` | Detect confirmed signatures for exposed sensitive files |
| `dir-listing` | Detect indexes, executable uploads, and active SVG content |
| `login-protection` | Record visible login-protection indicators |
| `transport-security` | Identify sites that do not enforce HTTPS |
| `security-headers` | Identify missing browser defense-in-depth headers |

### A3. Run the Assessment

Recommended non-interactive commercial command:

```bash
./epx-recon https://client.example \
  --authorize \
  --authorization-ref SOW-2026-014 \
  --operator "Analyst Name" \
  --client "Client Organization" \
  --output reports/EPX-CLIENT-2026-014-scan.json
```

Replace every example value with the real engagement information.

The command creates:

```text
reports/EPX-CLIENT-2026-014-scan.json
reports/EPX-CLIENT-2026-014-scan.json.sha256
```

The JSON is the authoritative machine-readable assessment record. The sidecar
contains its SHA-256 digest.

### A4. Understand Authorization Modes

For scheduled or automated operation, use:

```bash
--authorize --authorization-ref SOW-2026-014
```

Without `--authorize`, the program asks the operator to type `AUTHORIZED` and
enter an authorization reference. Cancelling this prompt returns exit code 2
and sends no assessment requests.

`--authorize` is an operator affirmation. It does not replace written
permission.

### A5. Check Completion

Review the terminal result and the JSON field named `status`.

| JSON status | Meaning | Required action |
|---|---|---|
| `complete` | All selected checks completed | Continue to verification |
| `incomplete` | One or more checks did not complete | Investigate before reporting |
| `failed` | The assessment could not be completed | Correct the cause and rerun |

`epx-recon` returns exit code 0 only for a complete scan. A nonzero exit code
must be investigated, but the JSON may still contain useful partial evidence.

### A6. Verify the Scan Artifact

```bash
./epx-verify reports/EPX-CLIENT-2026-014-scan.json
```

Expected output:

```text
verified: reports/EPX-CLIENT-2026-014-scan.json
sha256: 0123456789abcdef...
```

Do not continue when verification reports:

- `SHA-256 mismatch`;
- `no SHA-256 sidecar found`;
- `invalid epxtool JSON`.

Investigate the artifact, restore it from a trusted source, or rerun the
assessment. Do not create a new sidecar merely to hide an unexplained mismatch.

### A7. Perform Analyst Review

Open the JSON and review:

- `status` and `errors`;
- `target`, `scope`, and authorization details;
- every check in `checks`;
- every finding's severity, confidence, summary, evidence, and recommendation;
- supporting request IDs;
- request errors, truncation, and redirect behavior;
- component versions and any CVE candidates;
- false positives, duplicate findings, and business context.

The analyst must understand these limitations:

- a public author slug is not necessarily a login name;
- a component reference does not prove that the component is active;
- a public version string may not match deployed code;
- missing visible login controls do not prove that server-side controls are absent;
- a CVE correlation is a candidate match, not proof of exploitability;
- no findings does not mean the site is secure.

Do not use `--reviewed-by` until this review is complete.

### A8. Generate Draft Reports

Generate Markdown:

```bash
./epx-report reports/EPX-CLIENT-2026-014-scan.json \
  --format md \
  --output reports/EPX-CLIENT-2026-014-report.md \
  --client-name "Client Organization" \
  --report-id EPX-CLIENT-2026-014
```

Generate HTML:

```bash
./epx-report reports/EPX-CLIENT-2026-014-scan.json \
  --format html \
  --output reports/EPX-CLIENT-2026-014-report.html \
  --client-name "Client Organization" \
  --report-id EPX-CLIENT-2026-014
```

Without `--reviewed-by`, both reports are marked:

```text
AUTOMATED DRAFT - ANALYST REVIEW REQUIRED
```

### A9. Generate Reviewed Reports

After completing the analyst review, regenerate the reports with the reviewer's
real name:

```bash
./epx-report reports/EPX-CLIENT-2026-014-scan.json \
  --format html \
  --output reports/EPX-CLIENT-2026-014-report.html \
  --client-name "Client Organization" \
  --reviewed-by "Analyst Name" \
  --report-id EPX-CLIENT-2026-014
```

Repeat with `--format md` if a reviewed Markdown report is required.

`epx-report` checks an existing input JSON sidecar before generating a report.
It stops on an integrity mismatch.

Do not use `--ignore-integrity` during normal operations. It is only for a
documented recovery investigation after the mismatch has been understood.

### A10. Verify the Final Reports

```bash
./epx-verify reports/EPX-CLIENT-2026-014-report.md
./epx-verify reports/EPX-CLIENT-2026-014-report.html
```

Open the HTML report in a browser and check:

- client, target, report ID, and authorization reference;
- analyst attribution;
- executive summary;
- finding order and severity;
- evidence formatting;
- recommendations;
- draft or reviewed status;
- accidental disclosure of data outside the engagement.

### A11. Prepare the Delivery Package

The minimum internal case package is:

```text
EPX-CLIENT-2026-014-scan.json
EPX-CLIENT-2026-014-scan.json.sha256
EPX-CLIENT-2026-014-report.html
EPX-CLIENT-2026-014-report.html.sha256
```

Include Markdown and its sidecar when contractually required.

Deliver reports using the approved encrypted channel. Do not send the raw JSON
unless the contract or client procedure requires it.

## External Assessment Controls

Default controls:

| Setting | Default | Allowed range |
|---|---:|---:|
| Request timeout | 10 seconds | Greater than 0, maximum 120 |
| Delay between requests | 0.1 seconds | 0 to 10 |
| Request budget | 100 | 1 to 1000 |
| Maximum response size | 2 MB | Greater than 0, maximum 10 MB |
| TLS verification | Enabled | Disable only with `--insecure` |

For a fragile or rate-sensitive target:

```bash
./epx-recon https://client.example \
  --authorize \
  --authorization-ref SOW-2026-014 \
  --operator "Analyst Name" \
  --client "Client Organization" \
  --delay 0.5 \
  --max-requests 60 \
  --timeout 8 \
  --max-response-mb 1 \
  --output reports/EPX-CLIENT-2026-014-scan.json
```

Run only approved checks:

```bash
./epx-recon https://client.example \
  --authorize \
  --authorization-ref SOW-2026-014 \
  --operator "Analyst Name" \
  --client "Client Organization" \
  --only transport-security,security-headers \
  --output reports/EPX-CLIENT-2026-014-headers.json
```

Use `--insecure` only for an explicitly approved test environment with a known
self-signed or otherwise untrusted certificate. The setting is recorded in the
scan JSON.

## Optional CVE Correlation

CVE correlation is off by default. The supported source is WPScan.

Enabling it sends detected component slugs and reported versions to a
third-party service. Obtain specific approval before allowing client inventory
to leave the engagement boundary.

Set the API key without placing it in shell history:

```bash
read -s WPSCAN_API_KEY
export WPSCAN_API_KEY
```

Run the assessment:

```bash
./epx-recon https://client.example \
  --authorize \
  --authorization-ref SOW-2026-014 \
  --operator "Analyst Name" \
  --client "Client Organization" \
  --cve-source wpscan \
  --output reports/EPX-CLIENT-2026-014-scan.json
```

Remove the key from the current shell afterward:

```bash
unset WPSCAN_API_KEY
```

CVE interpretation rules:

- matches are candidates that require analyst validation;
- reported component versions may be inaccurate;
- a version match does not prove that the vulnerable code is active or reachable;
- feed failures are recorded and can make the assessment incomplete;
- do not state that exploitation occurred based only on a CVE match.

## Workflow B: Incident Evidence Analysis

Use this workflow when a client supplies access logs, suspicious server files,
configuration files, or a database dump.

`epx-forensics` performs offline static analysis. It does not contact the
affected website and does not execute supplied PHP.

### B1. Receive and Preserve Evidence

1. Record who supplied the evidence, when it was received, and by which channel.
2. Record the incident or ticket reference.
3. Preserve the original files in a restricted, read-only location.
4. Analyze a working copy, not the only available original.
5. Do not manually extract or execute suspicious archives or scripts.
6. Record any known source timezone and collection method.

Example case structure:

```text
cases/IR-CLIENT-2026-001/
|-- originals/
|-- working/
|   |-- accesslogs/
|   |   |-- access.log
|   |   `-- older-access.log.gz
|   |-- suspicious.php
|   `-- database.sql
`-- reports/
```

The analyzer accepts a single file or a folder. Supported archive formats are:

- `.gz`;
- `.zip`;
- `.tar`;
- `.tar.gz`;
- `.tgz`.

Archive safety limits:

| Limit | Value |
|---|---:|
| Maximum regular-file members | 5,000 |
| Maximum expanded member size | 100 MB |
| Maximum total expanded archive size | 500 MB |

Archives are read without extracting members to disk. Parent traversal paths,
links, and device entries are rejected.

### B2. Name Access Logs Clearly

Use recognizable access-log names or place logs in an `accesslogs` directory.
Examples:

```text
access.log
access.log.gz
client-accesslog.zip
client-ssl_log
accesslogs/client.example
```

The parser expects Apache combined-style access-log records. Malformed or
unsupported lines are counted and reported rather than silently treated as
valid.

### B3. Run Offline Analysis

From the tool directory:

```bash
./epx-forensics ../cases/IR-CLIENT-2026-001/working \
  --case-id IR-CLIENT-2026-001 \
  --site client.example \
  --authorization-ref INCIDENT-TICKET-2026-001 \
  --operator "Analyst Name" \
  --client "Client Organization" \
  --output reports/IR-CLIENT-2026-001-forensics.json
```

The command creates:

```text
reports/IR-CLIENT-2026-001-forensics.json
reports/IR-CLIENT-2026-001-forensics.json.sha256
```

The analyzer records:

- hashes, sizes, paths, types, and modification times for supplied sources;
- safe archive-member metadata;
- duplicate log content;
- parsed and malformed log counts;
- login attacks and high-volume PHP probing;
- likely nonbaseline backdoor interactions;
- static PHP and server-configuration indicators;
- conservative SQL injection pattern results;
- timeline events, indicators, findings, and limitations.

### B4. Check Processing Status

Open the forensic JSON and review `status` and `errors`.

| JSON status | Meaning | Required action |
|---|---|---|
| `complete` | All accepted evidence was processed | Continue |
| `incomplete` | Some evidence could not be processed | Investigate every error |
| `failed` | Analysis could not be completed | Correct the source or command |

`epx-forensics` returns exit code 0 for `complete` and `incomplete`, so the
operator must review the JSON status. It returns exit code 1 for `failed`.

### B5. Verify the Forensic Artifact

```bash
./epx-verify reports/IR-CLIENT-2026-001-forensics.json
```

Do not continue after a mismatch, missing sidecar, or schema error.

### B6. Perform Incident Analyst Review

Review:

- the evidence manifest and every SHA-256 value;
- source and archive-member paths;
- processing errors and parser statistics;
- duplicate evidence counts;
- the compromise assessment;
- initial-access and database-injection assessments;
- every finding's severity and confidence;
- every timeline event and its `timestamp_basis`;
- indicators, source IPs, URL paths, and file hashes;
- whether response sizes represent real content or a soft-404 baseline;
- whether filesystem times came from the affected server or a copied file;
- SQL matches in their original database context.

Do not make unsupported claims:

- access logs show requests and responses, not command output;
- HTTP 200 does not always mean a requested file existed;
- login attempts do not prove successful authentication;
- filesystem modification times can be copied or altered;
- a suspicious filename alone does not prove malware;
- no SQL pattern match does not prove the database is clean;
- available logs may begin after initial compromise.

### B7. Generate an Incident Draft

Markdown:

```bash
./epx-report reports/IR-CLIENT-2026-001-forensics.json \
  --format md \
  --output reports/IR-CLIENT-2026-001-incident-report.md \
  --client-name "Client Organization" \
  --report-id IR-CLIENT-2026-001
```

HTML:

```bash
./epx-report reports/IR-CLIENT-2026-001-forensics.json \
  --format html \
  --output reports/IR-CLIENT-2026-001-incident-report.html \
  --client-name "Client Organization" \
  --report-id IR-CLIENT-2026-001
```

The draft remains marked for analyst review.

### B8. Generate the Reviewed Incident Report

Only after completing the incident review:

```bash
./epx-report reports/IR-CLIENT-2026-001-forensics.json \
  --format html \
  --output reports/IR-CLIENT-2026-001-incident-report.html \
  --client-name "Client Organization" \
  --reviewed-by "Analyst Name" \
  --report-id IR-CLIENT-2026-001
```

### B9. Verify and Inspect the Final Report

```bash
./epx-verify reports/IR-CLIENT-2026-001-incident-report.md
./epx-verify reports/IR-CLIENT-2026-001-incident-report.html
```

Before delivery, confirm:

- timestamps include their timezone or UTC offset;
- timestamp limitations are visible;
- attempts and confirmed activity are clearly separated;
- initial access is not guessed;
- sensitive database records, credentials, tokens, and personal data are absent;
- indicators are appropriate to share with the client;
- recommendations match the evidence and incident severity.

### B10. Preserve the Case Package

The internal forensic package should contain:

```text
IR-CLIENT-2026-001-forensics.json
IR-CLIENT-2026-001-forensics.json.sha256
IR-CLIENT-2026-001-incident-report.html
IR-CLIENT-2026-001-incident-report.html.sha256
```

Retain the original evidence separately according to the contract and
chain-of-custody procedure. Do not place client evidence in this source
repository.

## Command Reference

### `epx-recon`

```text
./epx-recon TARGET [options]
```

Important options:

| Option | Meaning |
|---|---|
| `-o`, `--output` | Save JSON to a file instead of standard output |
| `--authorize` | Non-interactive authorization affirmation |
| `--authorization-ref` | Written authorization, SOW, or ticket reference |
| `--operator` | Person operating the assessment |
| `--client` | Client name stored in the JSON |
| `--timeout` | Per-request timeout in seconds |
| `--delay` | Minimum delay between requests |
| `--max-requests` | Hard request budget |
| `--max-response-mb` | Per-response size limit |
| `--only` | Comma-separated check IDs |
| `--insecure` | Disable TLS certificate validation |
| `--cve-source wpscan` | Enable approved third-party CVE correlation |
| `--cve-api-key` | Supply the WPScan key directly |
| `--list-checks` | Print available check IDs |
| `--quiet` | Suppress progress messages |

### `epx-forensics`

```text
./epx-forensics SOURCE --case-id ID --authorization-ref REF \
  --operator NAME --client CLIENT --output RESULT.json
```

All options except `--site` are required.

### `epx-report`

```text
./epx-report INPUT.json --format md|html --output REPORT
```

Important options:

| Option | Meaning |
|---|---|
| `--format md` | Generate Markdown |
| `--format html` | Generate self-contained HTML |
| `--client-name` | Client name displayed in the report |
| `--report-id` | Engagement or report identifier |
| `--reviewed-by` | Mark the report reviewed by the named analyst |
| `--ignore-integrity` | Continue after an investigated JSON mismatch |

### `epx-verify`

```text
./epx-verify ARTIFACT
```

For JSON artifacts, this verifies both the SHA-256 sidecar and the schema. For
Markdown and HTML reports, it verifies the SHA-256 sidecar.

## Exit Codes

| Program | Code | Meaning |
|---|---:|---|
| `epx-recon` | 0 | Scan status is complete |
| `epx-recon` | 1 | Incomplete/failed scan or output error |
| `epx-recon` | 2 | Invalid arguments or authorization cancelled |
| `epx-forensics` | 0 | Result is complete or incomplete |
| `epx-forensics` | 1 | Result failed or could not be saved |
| `epx-forensics` | 2 | Invalid command arguments |
| `epx-report` | 0 | Report generated successfully |
| `epx-report` | 1 | Input, schema, integrity, or output error |
| `epx-report` | 2 | Invalid command arguments |
| `epx-verify` | 0 | Artifact verified |
| `epx-verify` | 1 | Mismatch, invalid JSON, or read error |
| `epx-verify` | 2 | SHA-256 sidecar is missing or arguments are invalid |

Always review the JSON `status`; do not rely only on the process exit code.

## Troubleshooting

### Permission denied

```bash
chmod +x epx-recon epx-forensics epx-report epx-verify
```

### Command not found

Confirm the terminal is in the `tool` directory:

```bash
pwd
ls -l epx-recon epx-forensics epx-report epx-verify
```

Use `./epx-recon` from the source folder or activate the virtual environment.

### Target cannot be reached

Check:

- the hostname and URL scheme;
- DNS or `/etc/hosts`;
- firewall and proxy requirements;
- whether the authorized site is currently running;
- whether the authorization window is active.

Do not change to a different hostname without confirming scope.

### TLS certificate error

Correct the target certificate where possible. Use `--insecure` only for an
explicitly approved test environment and document why it was required.

### Unknown check ID

```bash
./epx-recon --list-checks
```

Pass exact IDs separated by commas with no extra descriptive text.

### Request limit reached

Review whether the selected checks require a larger approved budget. Increase
`--max-requests` only when it is safe for the target and remains within scope.

### SHA-256 mismatch

Stop the workflow. Determine whether the artifact was edited, transferred
incorrectly, corrupted, or replaced. Restore or rerun from trusted evidence.

Do not use `--ignore-integrity` merely to make report generation continue.

### Missing sidecar

The artifact is incomplete as a delivery package. Locate the original sidecar
or regenerate the artifact from its trusted source.

### Forensic archive rejected

Review the JSON `errors`. Common causes include:

- unsafe parent traversal paths;
- symlinks, hard links, or device entries;
- too many members;
- an oversized member;
- total expanded size over the limit;
- a damaged or unsupported archive.

Do not bypass archive protections by extracting suspicious content into the
tool directory.

### Report still says automated draft

Complete the analyst review, then regenerate with:

```bash
--reviewed-by "Analyst Name"
```

Never add review attribution only to remove the draft warning.

## Data Handling

Assessment artifacts can contain:

- client hostnames and infrastructure details;
- public user names and slugs;
- software inventory and versions;
- security findings and indicators;
- malicious file paths and hashes;
- source IP addresses and incident timelines.

Required controls:

- restrict access by case and role;
- encrypt artifacts at rest and in transit;
- use an approved case-transfer channel;
- keep raw evidence separate from generated reports;
- do not commit client artifacts to source control;
- do not upload evidence to unapproved third parties;
- retain and delete data according to the contract;
- remove temporary working copies after approved retention ends.

## Interpretation and Scope Limits

The external scanner is read-only. It reads public resources and sends one
XML-RPC method-list request. It does not log in, guess credentials, exploit a
vulnerability, delete data, or modify the target.

The scanner deliberately does not request discovered PHP uploads because a GET
request could execute server-side code.

MITRE ATT&CK mappings in external assessment findings are reference mappings.
They do not prove that an adversary used the listed technique.

The forensic analyzer provides evidence correlation, not full disk forensics,
memory forensics, malware reverse engineering, or a complete root-cause
determination. Initial access can remain undetermined when the available
evidence starts after compromise.

## Quality and Release Checks

Before distributing a new tool version, run:

```bash
make check
```

This runs:

- unit tests;
- Python compilation;
- `mypy`;
- error-level `pylint`.

Related documents:

- [CHANGELOG.md](CHANGELOG.md)
- [SECURITY.md](SECURITY.md)
- [LICENSE.md](LICENSE.md)

Only the latest released version listed in the changelog is supported.

## Final Operator Checklist

### External assessment

- [ ] Written authorization and exact scope confirmed
- [ ] Case ID, client, operator, and authorization reference recorded
- [ ] Correct target and testing window confirmed
- [ ] Scan JSON created
- [ ] JSON status reviewed
- [ ] JSON integrity and schema verified
- [ ] Findings manually reviewed
- [ ] Draft report inspected
- [ ] Reviewed report generated with accurate attribution
- [ ] Final report integrity verified
- [ ] Delivery package transferred securely
- [ ] Retention date recorded

### Incident evidence

- [ ] Evidence receipt and source recorded
- [ ] Originals preserved separately
- [ ] Working copy prepared
- [ ] Case ID, site, client, operator, and reference recorded
- [ ] Forensic JSON created
- [ ] Processing errors and status reviewed
- [ ] JSON integrity and schema verified
- [ ] Timeline, confidence, timestamps, and limitations reviewed
- [ ] Sensitive data checked before delivery
- [ ] Reviewed incident report generated
- [ ] Final report integrity verified
- [ ] Evidence and reports retained according to policy

Only assess systems and evidence covered by clear written authorization.
