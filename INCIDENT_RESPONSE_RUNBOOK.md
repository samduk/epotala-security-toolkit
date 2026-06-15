# EPX WordPress Incident Response Runbook

This is the operating procedure for analyzing a suspected WordPress compromise
with EPX Toolkit. It is designed for cases that may include a complete website,
access logs, authentication logs, archives, and a SQL dump.

EPX automates evidence inventory and first-pass analysis. It does not replace
incident command, legal review, business-impact assessment, containment,
trusted recovery, or analyst judgment.

## 1. Roles and Required Records

Assign these roles before analysis starts. One person may hold several roles on
a small engagement, but ownership must be explicit.

| Role | Responsibility |
|---|---|
| Incident lead | Scope, priorities, approvals, status, and client decisions |
| Evidence custodian | Receipt record, hashes, originals, access, and transfers |
| Incident analyst | Tool execution, validation, timeline, and technical conclusions |
| System owner | Containment, rebuild, recovery, and operational validation |
| Business or legal owner | Impact, notification, contractual, and regulatory decisions |
| Peer reviewer | Independent review of claims, evidence, severity, and redaction |

Create or obtain:

- written authorization, SOW, or incident ticket;
- a unique case ID;
- affected hostname and hosting environment;
- evidence receipt time, source, transfer method, and source timezone;
- the client's current incident state: `unknown`, `active`, `contained`,
  `eradicated`, or `recovered`;
- a communication and escalation contact;
- retention and secure-deletion requirements.

Do not begin active testing against the affected site unless it is separately
authorized. EPX Forensics is offline and does not contact the site.

## 2. Create the Case Workspace

Use a case folder outside the toolkit repository:

```bash
export CASE_ID="IR-CLIENT-2026-001"
export CASE_ROOT="$HOME/cases/$CASE_ID"

mkdir -p \
  "$CASE_ROOT/originals" \
  "$CASE_ROOT/working" \
  "$CASE_ROOT/reports" \
  "$CASE_ROOT/notes"

chmod 700 "$CASE_ROOT"
```

Recommended structure:

```text
IR-CLIENT-2026-001/
|-- originals/       Received evidence, preserved without modification
|-- working/         Verified copies used by EPX and the analyst
|-- notes/           Intake, decisions, manual validation, and peer review
`-- reports/         JSON artifacts, sidecars, and client reports
```

Never place client evidence or reports in the EPX source repository.

## 3. Receive and Preserve Evidence

Record the transfer before changing file names, extracting archives, or opening
the website project in an IDE.

The intake note should contain:

```text
Case ID:
Received at:
Received from:
Transfer method:
Evidence description:
Source host:
Source timezone:
Collector and collection commands:
Original storage location:
Originals preserved separately:
Known gaps:
```

Copy received evidence into `originals/`, restrict permissions, and create a
recursive SHA-256 manifest:

```bash
chmod -R go-rwx "$CASE_ROOT/originals"

find "$CASE_ROOT/originals" -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > "$CASE_ROOT/notes/original-sha256.txt"
```

Create the working copy and verify that it initially matches:

```bash
cp -a "$CASE_ROOT/originals/." "$CASE_ROOT/working/"

(
  cd "$CASE_ROOT/working"
  find . -type f -print0 | sort -z | xargs -0 sha256sum
) > "$CASE_ROOT/notes/working-sha256.txt"
```

Keep originals separately preserved. Do not run suspicious PHP, JavaScript,
shell scripts, binaries, Office macros, or database content.

## 4. Check Acquisition Completeness

Request the widest practical time window, including rotated and compressed
logs. A complete acquisition normally includes:

| Evidence area | Preferred content |
|---|---|
| Web logs | Access and error logs, rotated logs, reverse-proxy, CDN, WAF, and hosting-panel logs |
| Authentication | `/var/log/auth.log`, `/var/log/secure`, relevant journal exports, SSH, SFTP, FTP, and control-panel access |
| WordPress project | Entire document root, hidden files, `wp-admin`, `wp-includes`, `wp-content`, root PHP files, `.htaccess`, and server overrides |
| Configuration | `wp-config.php`, web-server virtual host, PHP configuration, cron, scheduled tasks, and environment settings |
| Database | Consistent SQL dump with table prefixes and export time recorded |
| Accounts | WordPress administrators, operating-system users, hosting users, API keys, and service accounts |
| Baselines | Known-good backup, deployment artifact, vendor package, or prior file hashes |
| Environment | Hostname, operating system, PHP, web server, WordPress version, architecture, and source timezone |

Do not delay emergency containment solely to obtain every item. Record missing
evidence and explain how each gap limits the conclusions.

The analyzer accepts plain files and `.gz`, `.zip`, `.tar`, `.tar.gz`, and
`.tgz` archives. It reads supported archives without extracting them to disk.
Archive links, devices, parent traversal, and excessive expansion are rejected.

## 5. Prepare the Working Evidence

Keep original names when possible. These names are recognized:

```text
access.log
access.log.1
access.log.gz
site-accesslog.zip
site-ssl_log
auth.log
auth.log.1.gz
secure
database.sql
```

The access-log parser expects Apache combined-style records. Authentication
analysis supports common Linux SSH and local account events in RFC 3164 or
ISO-8601 syslog records.

For traditional syslog records without a year or UTC offset, provide the source
timezone. EPX infers the year from evidence metadata and clearly labels that
timestamp limitation.

## 6. Run EPX Forensics

From the EPX Toolkit directory:

```bash
cd /path/to/epotala-security-toolkit
```

Run the complete command. Replace every example value:

```bash
./epx-forensics "$CASE_ROOT/working" \
  --case-id "$CASE_ID" \
  --site "client.example" \
  --authorization-ref "INCIDENT-TICKET-2026-001" \
  --operator "Analyst Name" \
  --client "Client Organization" \
  --received-at "2026-06-14T10:30:00+05:30" \
  --received-from "Client Contact or Collection System" \
  --collection-method "Encrypted client transfer" \
  --source-timezone "Asia/Kolkata" \
  --originals-preserved \
  --incident-state active \
  --output "$CASE_ROOT/reports/$CASE_ID-forensics.json"
```

Use `--originals-preserved` only when preservation is actually confirmed. Use
`--incident-state unknown` when the current state has not been validated.

The command creates:

```text
$CASE_ID-forensics.json
$CASE_ID-forensics.json.sha256
```

## 7. Verify the Analysis Artifact

```bash
./epx-verify "$CASE_ROOT/reports/$CASE_ID-forensics.json"
```

Stop and investigate when:

- the sidecar is missing or mismatched;
- schema validation fails;
- JSON `status` is `failed`;
- JSON `status` is `incomplete` and an error affects a material evidence source;
- the coverage matrix incorrectly classifies an expected source.

`incomplete` does not automatically invalidate the case. The analyst must state
which evidence failed and how that affects confidence.

## 8. Perform the Technical Review

Review the JSON in this order.

### 8.1 Intake and coverage

Confirm:

- receipt metadata is accurate;
- original preservation is not overstated;
- source timezone is correct;
- every expected evidence category is `analyzed`, `partial`, or
  `not-provided` as appropriate;
- archive errors and malformed-line counts are understood.

### 8.2 Authentication and accounts

Validate:

- failed and successful SSH activity;
- successful access after repeated failures;
- root access;
- account creation and privilege changes;
- source IP ownership and expected administrator locations;
- WordPress administrator creation, password resets, and session activity from
  database and application evidence.

A successful authentication log entry proves acceptance, not authorization.
Confirm it with the owner and available session or command history.

### 8.3 Access logs

Determine:

- earliest suspicious request;
- exploit or credential-attack candidates;
- upload, web-shell, command, and callback paths;
- source IPs and user agents;
- response-code and response-size baselines;
- repeated access to discovered artifacts;
- the last observed malicious action.

HTTP 200 does not by itself prove exploitation. Access logs do not provide
command output, process execution, or database-write confirmation.

### 8.4 WordPress files

Review:

- WordPress core presence and observed version;
- unexpected root files and hidden files;
- PHP in `wp-content/uploads`;
- recently modified plugins and themes;
- plugin or theme files that do not match trusted vendor packages;
- `.htaccess`, PHP configuration, cron, and scheduled tasks;
- web shells, uploaders, loaders, obfuscation, and persistence.

EPX performs static indicator analysis. Before declaring the project clean,
compare core, plugins, and themes against trusted packages or a known-good
deployment. Do not execute suspect code.

### 8.5 SQL dump

Review matched records in an isolated database copy. Check:

- WordPress administrators and privilege changes;
- injected scripts, iframes, redirects, and PHP;
- malicious options, widgets, posts, and serialized content;
- unauthorized plugin activation and scheduled-task data;
- evidence of the write path and affected records.

A pattern match is a lead, not automatic proof. No match is not proof that the
database is clean.

### 8.6 Timeline and scope

Create one normalized timeline while retaining the original timestamp and its
basis. Separate:

- confirmed facts;
- high-confidence conclusions;
- possible explanations;
- unknowns.

Address:

- earliest known malicious activity;
- possible initial-access vectors;
- execution and persistence;
- affected accounts, files, database records, and hosts;
- attacker actions and likely objectives;
- containment, eradication, and recovery milestones;
- evidence gaps that prevent root-cause determination.

Do not guess initial access. It may remain `undetermined`.

## 9. Contain, Eradicate, and Recover

These actions are human-owned and require client approval.

For a confirmed or likely active compromise:

1. Preserve required volatile and persistent evidence.
2. Isolate affected systems or restrict access according to the incident plan.
3. Disable or reset compromised accounts and sessions.
4. Rotate passwords, API keys, salts, tokens, SSH keys, database credentials,
   hosting credentials, and recovery channels from a known-clean system.
5. Identify persistence before removing artifacts.
6. Rebuild from trusted sources instead of deleting only known malicious files.
7. Restore validated content and database data.
8. Patch WordPress, plugins, themes, PHP, the operating system, and exposed
   management services.
9. Verify file integrity, account lists, scheduled tasks, and configuration.
10. Return to service with enhanced logging and monitoring.

Record who approved each action, the exact time, and the validation result.

## 10. Generate the Draft Report

Markdown:

```bash
./epx-report "$CASE_ROOT/reports/$CASE_ID-forensics.json" \
  --format md \
  --output "$CASE_ROOT/reports/$CASE_ID-incident-report.md" \
  --client-name "Client Organization" \
  --report-id "$CASE_ID-R1"
```

HTML:

```bash
./epx-report "$CASE_ROOT/reports/$CASE_ID-forensics.json" \
  --format html \
  --output "$CASE_ROOT/reports/$CASE_ID-incident-report.html" \
  --client-name "Client Organization" \
  --report-id "$CASE_ID-R1"
```

The report remains marked `AUTOMATED DRAFT` until analyst review is recorded.

## 11. Peer Review and Quality Gate

Before using `--reviewed-by`, confirm:

- case, client, scope, authorization, and receipt metadata are correct;
- coverage gaps are visible and reflected in limitations;
- compromise status and severity match the evidence;
- business impact is supplied by an authorized owner or remains not assessed;
- timeline times, offsets, year assumptions, and timestamp bases are correct;
- attempts are separated from successful or confirmed activity;
- every High or Critical finding has sufficient supporting evidence;
- findings do not reveal passwords, tokens, personal data, or unnecessary SQL
  content;
- recommendations are prioritized and feasible;
- containment and recovery are not claimed without owner confirmation;
- notification considerations were reviewed;
- a second person reviewed material claims when the engagement permits it.

## 12. Generate and Verify the Reviewed Report

```bash
./epx-report "$CASE_ROOT/reports/$CASE_ID-forensics.json" \
  --format html \
  --output "$CASE_ROOT/reports/$CASE_ID-incident-report.html" \
  --client-name "Client Organization" \
  --reviewed-by "Analyst Name" \
  --report-id "$CASE_ID-R1"

./epx-verify "$CASE_ROOT/reports/$CASE_ID-incident-report.html"
```

Deliver only the approved report and agreed supporting artifacts through the
authorized secure channel. Keep raw evidence internal unless the contract
requires its return.

## 13. Notification and Escalation

The technical report provides facts that can support notification decisions.
It does not determine legal obligations.

The incident lead and authorized business or legal owner must assess:

- applicable law and regulation;
- contractual and cyber-insurance notice periods;
- affected individuals, partners, payment providers, or grant authorities;
- law-enforcement reporting;
- CISA reporting or voluntary information sharing;
- public communication and reputational risk.

Preserve the decision, owner, time, and rationale even when no notification is
made.

## 14. Close the Case

After recovery:

1. Confirm monitoring has not identified recurrence.
2. Complete a lessons-learned review.
3. Record root cause as confirmed, likely, possible, or undetermined.
4. Assign corrective actions, owners, and due dates.
5. Update detection, backups, hardening, access control, and collection
   procedures.
6. Apply the contractual retention schedule.
7. Securely delete working copies when authorized, while preserving required
   records and proof of disposition.

## Standards and Practice Alignment

This runbook is informed by:

- NIST SP 800-61 Rev. 3 and NIST Cybersecurity Framework 2.0;
- CISA Federal Government Cybersecurity Incident and Vulnerability Response
  Playbooks;
- CISA chain-of-custody guidance;
- CISA incident-reporting guidance and legacy US-CERT notification guidance;
- public incident-response practices from AWS, Microsoft, Google, Netflix, and
  Meta, including explicit ownership, do-no-harm evidence handling, targeted
  collection, automation with human validation, known-good recovery, and
  lessons learned.

There is no single formal “FAANG incident-response standard.” EPX applies
publicly documented hyperscale practices where they are useful and proportionate.
This runbook is not a certification of compliance with any framework,
government program, or company standard.

Primary references:

- NIST SP 800-61 Rev. 3:
  <https://csrc.nist.gov/pubs/sp/800/61/r3/final>
- CISA Federal Incident Response Playbooks:
  <https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks>
- CISA chain-of-custody guidance:
  <https://www.cisa.gov/resources-tools/resources/cisa-insights-chain-custody-and-critical-infrastructure-systems>
- CISA incident reporting:
  <https://www.cisa.gov/reporting-cyber-incident>
- Legacy US-CERT Federal Incident Notification Guidelines:
  <https://www.cisa.gov/federal-incident-notification-guidelines>
- AWS Security Incident Response Guide:
  <https://docs.aws.amazon.com/security-ir/latest/userguide/introduction.html>
- Microsoft incident-response overview:
  <https://learn.microsoft.com/en-us/security/operations/incident-response-overview>
- Google cloud forensics practices:
  <https://cloud.google.com/transform/how-google-does-it-collecting-and-analyzing-cloud-forensics>
- Netflix Dispatch:
  <https://netflixtechblog.com/introducing-dispatch-da4b8a2a8072>
- Meta security incident-response preparation:
  <https://engineering.fb.com/2014/11/05/security/security-scale-2014-recap/>
