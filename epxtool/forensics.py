"""Offline incident-evidence analysis for access logs, archives, PHP, and SQL."""

import gzip
import hashlib
import io
import os
import re
import stat
import tarfile
import uuid
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import __version__

MAX_MEMBER_BYTES = 100 * 1024 * 1024
MAX_TOTAL_ARCHIVE_BYTES = 500 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5000
MAX_STATIC_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024
FORENSICS_SCHEMA_VERSION = "1.1"

LOG_PATTERN = re.compile(
    rb'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    rb'"(?P<method>[A-Z]+) (?P<target>\S+) [^"]+" '
    rb'(?P<status>[0-9]{3}) (?P<size>[0-9-]+)'
)
SENSITIVE_PATTERN = re.compile(
    r"(?i)(password|passwd|token|secret|authcode|api[_-]?key)"
    r"(\s*[:=]\s*|[\"']\s*,\s*[\"'])([^,\s\"']+)"
)
EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHP_NAME_PATTERN = re.compile(r"(?i)\.p(?:hp[0-9]?|html)(?:$|[/?])")
SHELL_NAME_PATTERN = re.compile(
    r"(?i)(?:^|/)(?:x|wso|shell|cmd|bypass|uploader|upload|mini|alfa|"
    r"priv8|marijuana|fox|wp-console|filemanager)[^/]*\.p(?:hp[0-9]?|html)$"
)
AUTH_FAILED_PATTERN = re.compile(
    r"(?i)failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-f:.]+)"
)
AUTH_ACCEPTED_PATTERN = re.compile(
    r"(?i)accepted (?P<method>\S+) for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-f:.]+)"
)
AUTH_USERADD_PATTERN = re.compile(
    r"(?i)(?:new user: name=|useradd(?:\[[0-9]+\])?:.*new user: name=)"
    r"(?P<user>[a-z0-9._-]+)"
)
RFC3164_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>[ 0-9][0-9])\s+"
    r"(?P<clock>[0-9]{2}:[0-9]{2}:[0-9]{2})"
)
ISO_SYSLOG_PATTERN = re.compile(
    r"^(?P<time>[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2}))"
)

METHODOLOGY = [
    {
        "framework": "NIST SP 800-61 Rev. 3 and NIST CSF 2.0",
        "application": (
            "Evidence analysis supports Detect and Respond outcomes. The report "
            "tracks containment, eradication, recovery, and improvement as separate "
            "human-owned activities."
        ),
        "reference": "https://doi.org/10.6028/NIST.SP.800-61r3",
    },
    {
        "framework": "CISA Federal Incident Response Playbooks",
        "application": (
            "The workflow preserves evidence, establishes scope, records findings "
            "and status, and separates analysis from containment and recovery."
        ),
        "reference": (
            "https://www.cisa.gov/resources-tools/resources/"
            "federal-government-cybersecurity-incident-and-vulnerability-response-playbooks"
        ),
    },
    {
        "framework": "CISA chain-of-custody guidance",
        "application": (
            "Source hashes, paths, sizes, modification times, receipt metadata, and "
            "original-preservation status are recorded for evidence accountability."
        ),
        "reference": (
            "https://www.cisa.gov/resources-tools/resources/"
            "cisa-insights-chain-custody-and-critical-infrastructure-systems"
        ),
    },
    {
        "framework": "CISA incident reporting guidance",
        "application": (
            "The report captures facts useful for notification, but legal, regulatory, "
            "contractual, and CISA reporting obligations require case-specific review."
        ),
        "reference": "https://www.cisa.gov/reporting-cyber-incident",
    },
    {
        "framework": "Legacy US-CERT Federal Incident Notification Guidelines",
        "application": (
            "Notification data elements are retained as a useful reference where "
            "federal or contract-specific reporting requirements apply."
        ),
        "reference": (
            "https://www.cisa.gov/federal-incident-notification-guidelines"
        ),
    },
    {
        "framework": "Hyperscale incident-response practices",
        "application": (
            "The workflow uses explicit ownership, do-no-harm evidence handling, "
            "targeted analysis, automation with human validation, known-good recovery, "
            "and post-incident improvement practices reflected in AWS, Microsoft, "
            "Google, Netflix, and Meta engineering guidance."
        ),
        "reference": (
            "https://docs.aws.amazon.com/security-ir/latest/userguide/introduction.html"
        ),
    },
]


def utc_now():
    """Return a current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_stream(handle):
    """Hash a binary stream without retaining its contents."""
    digest = hashlib.sha256()
    while True:
        chunk = handle.read(1024 * 1024)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)


def sha256_bytes(data):
    """Return the SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def iso_mtime(path):
    """Return a filesystem modification time as an ISO timestamp."""
    return datetime.fromtimestamp(
        os.path.getmtime(path), tz=timezone.utc
    ).isoformat().replace("+00:00", "Z")


def safe_member_name(name):
    """Return True for a non-absolute archive member without parent traversal."""
    normalized = name.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    return bool(parts) and not normalized.startswith("/") and ".." not in parts


def read_bounded(handle, limit=MAX_MEMBER_BYTES):
    """Read at most limit bytes and reject larger content."""
    data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("content exceeds the " + str(limit) + "-byte limit")
    return data


def iter_bounded_lines(handle):
    """Yield bounded physical lines without retaining an oversized line."""
    line_number = 0
    while True:
        part = handle.readline(MAX_LINE_BYTES + 1)
        if not part:
            return
        line_number += 1
        oversized = len(part) > MAX_LINE_BYTES and not part.endswith(b"\n")
        sample = part[:MAX_LINE_BYTES]
        if oversized:
            while part and not part.endswith(b"\n"):
                part = handle.readline(MAX_LINE_BYTES + 1)
        yield line_number, sample, oversized


@dataclass
class EvidenceItem:
    """One plain file or safely read archive member."""

    name: str
    source_id: str
    reference: str
    size: int
    sha256: str
    modified_at: str
    path: str = ""
    data: bytes = b""

    def open(self):
        """Open the item as a binary stream."""
        if self.path:
            return open(self.path, "rb")
        return io.BytesIO(self.data)


def source_kind(path):
    """Return a simple evidence-container type."""
    lower = path.name.lower()
    if lower.endswith((".tar.gz", ".tgz", ".tar")):
        return "tar"
    if lower.endswith(".zip"):
        return "zip"
    if lower.endswith(".gz"):
        return "gzip"
    return "file"


def archive_items(path, source_id, modified_at):
    """Read archive members in memory with strict count and size limits."""
    kind = source_kind(path)
    items = []
    total = 0

    if kind == "gzip":
        with gzip.open(path, "rb") as handle:
            data = read_bounded(handle)
        name = path.name[:-3] or path.name + ".member"
        items.append(EvidenceItem(
            name=name,
            source_id=source_id,
            reference=source_id + ":M0001",
            size=len(data),
            sha256=sha256_bytes(data),
            modified_at=modified_at,
            data=data,
        ))
        return items

    if kind == "zip":
        with zipfile.ZipFile(path) as archive:
            members = [item for item in archive.infolist() if not item.is_dir()]
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ValueError("archive has too many members")
            for number, member in enumerate(members, start=1):
                if not safe_member_name(member.filename):
                    raise ValueError("unsafe archive member path: " + member.filename)
                if stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError("archive symlink is not allowed: " + member.filename)
                if member.file_size > MAX_MEMBER_BYTES:
                    raise ValueError("archive member is too large: " + member.filename)
                total += member.file_size
                if total > MAX_TOTAL_ARCHIVE_BYTES:
                    raise ValueError("archive expanded size exceeds the limit")
                with archive.open(member) as handle:
                    data = read_bounded(handle)
                items.append(EvidenceItem(
                    name=member.filename,
                    source_id=source_id,
                    reference=source_id + ":M" + str(number).zfill(4),
                    size=len(data),
                    sha256=sha256_bytes(data),
                    modified_at=modified_at,
                    data=data,
                ))
        return items

    if kind == "tar":
        with tarfile.open(path, "r:*") as archive:
            all_members = archive.getmembers()
            for member in all_members:
                if member.issym() or member.islnk() or member.isdev():
                    raise ValueError(
                        "archive link or device is not allowed: " + member.name
                    )
            members = [item for item in all_members if item.isfile()]
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ValueError("archive has too many regular-file members")
            for number, member in enumerate(members, start=1):
                if not safe_member_name(member.name):
                    raise ValueError("unsafe archive member path: " + member.name)
                if member.size > MAX_MEMBER_BYTES:
                    raise ValueError("archive member is too large: " + member.name)
                total += member.size
                if total > MAX_TOTAL_ARCHIVE_BYTES:
                    raise ValueError("archive expanded size exceeds the limit")
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                with extracted:
                    data = read_bounded(extracted)
                member_time = modified_at
                if member.mtime:
                    member_time = datetime.fromtimestamp(
                        member.mtime, tz=timezone.utc
                    ).isoformat().replace("+00:00", "Z")
                items.append(EvidenceItem(
                    name=member.name,
                    source_id=source_id,
                    reference=source_id + ":M" + str(number).zfill(4),
                    size=len(data),
                    sha256=sha256_bytes(data),
                    modified_at=member_time,
                    data=data,
                ))
        return items
    return items


def collect_evidence(source):
    """Build source manifests and logical evidence items."""
    root = Path(source).resolve()
    if not root.exists():
        raise ValueError("evidence source does not exist: " + str(root))
    paths = [root] if root.is_file() else sorted(
        path for path in root.rglob("*") if path.is_file()
    )
    manifests = []
    items = []
    errors = []
    for number, path in enumerate(paths, start=1):
        source_id = "EV-" + str(number).zfill(4)
        relative = path.name if root.is_file() else str(path.relative_to(root))
        kind = source_kind(path)
        modified_at = iso_mtime(path)
        with open(path, "rb") as handle:
            digest = sha256_stream(handle)
        manifest = {
            "id": source_id,
            "path": relative,
            "kind": kind,
            "size": path.stat().st_size,
            "sha256": digest,
            "modified_at": modified_at,
            "members": [],
        }
        if kind == "file":
            items.append(EvidenceItem(
                name=relative,
                source_id=source_id,
                reference=source_id,
                size=path.stat().st_size,
                sha256=digest,
                modified_at=modified_at,
                path=str(path),
            ))
        else:
            try:
                members = archive_items(path, source_id, modified_at)
                items.extend(members)
                manifest["members"] = [{
                    "reference": item.reference,
                    "path": item.name,
                    "size": item.size,
                    "sha256": item.sha256,
                    "modified_at": item.modified_at,
                } for item in members]
            except (OSError, ValueError, gzip.BadGzipFile, tarfile.TarError,
                    zipfile.BadZipFile) as error:
                errors.append(source_id + " could not be read: " + str(error))
        manifests.append(manifest)
    return manifests, items, errors


def redact(text):
    """Remove common credentials and personal email addresses from excerpts."""
    text = SENSITIVE_PATTERN.sub(r"\1\2[REDACTED]", text)
    return EMAIL_PATTERN.sub("[REDACTED EMAIL]", text)


def finding(title, severity, confidence, category, summary, evidence,
            source_ids, impact="", recommendation=""):
    """Build a stable forensic finding."""
    stable = hashlib.sha256(title.encode("utf-8")).hexdigest()[:10].upper()
    return {
        "id": "IR-" + stable,
        "category": category,
        "confidence": confidence,
        "title": title,
        "severity": severity,
        "summary": summary,
        "impact": impact,
        "recommendation": recommendation,
        "evidence": evidence,
        "source_ids": sorted(set(source_ids)),
    }


def parse_log_time(raw):
    """Parse an Apache access-log timestamp."""
    return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")


def is_auth_log_name(name):
    """Return True for common Linux authentication log names."""
    lower = name.lower().replace("\\", "/")
    basename = lower.rsplit("/", 1)[-1]
    return (
        basename.startswith("auth.log") or
        basename.startswith("secure") or
        basename.startswith("messages") or
        basename.startswith("journal") or
        "authlog" in basename
    )


def is_access_log_name(name):
    """Return True for common web access log names, excluding auth logs."""
    lower = name.lower()
    if is_auth_log_name(lower):
        return False
    return (
        "accesslog" in lower or "access.log" in lower or
        "ssl_log" in lower or lower.endswith((".log", "_log"))
    )


def parse_source_timezone(value):
    """Return a timezone and a note for operator-supplied source timezone text."""
    text = (value or "").strip()
    if not text:
        return timezone.utc, "source timezone not supplied; UTC assumed"
    if text.upper() in ("UTC", "Z"):
        return timezone.utc, "source timezone supplied as UTC"
    match = re.fullmatch(r"([+-])([0-9]{2}):([0-9]{2})", text)
    if match:
        minutes = int(match.group(2)) * 60 + int(match.group(3))
        if match.group(1) == "-":
            minutes = -minutes
        return timezone(timedelta(minutes=minutes)), "source timezone " + text
    try:
        return ZoneInfo(text), "source timezone " + text
    except ZoneInfoNotFoundError:
        return timezone.utc, (
            "unrecognized source timezone '" + text + "'; UTC assumed"
        )


def parse_auth_time(line, item, timezone_text):
    """Parse ISO or traditional syslog timestamps from an authentication log."""
    iso_match = ISO_SYSLOG_PATTERN.match(line)
    if iso_match:
        try:
            return (
                datetime.fromisoformat(
                    iso_match.group("time").replace("Z", "+00:00")
                ),
                "Authentication log ISO-8601 timestamp",
            )
        except ValueError:
            pass
    traditional = RFC3164_PATTERN.match(line)
    if not traditional:
        return None, ""
    try:
        item_time = datetime.fromisoformat(item.modified_at.replace("Z", "+00:00"))
        tzinfo, timezone_note = parse_source_timezone(timezone_text)
        parsed = datetime.strptime(
            str(item_time.year) + " " + traditional.group("month") + " " +
            traditional.group("day").strip() + " " + traditional.group("clock"),
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=tzinfo)
        return (
            parsed,
            "Authentication log local timestamp; year inferred from evidence "
            "modification time; " + timezone_note,
        )
    except ValueError:
        return None, ""


def suspicious_php_path(path):
    """Identify paths commonly used for web shells or hidden PHP loaders."""
    lower = path.lower()
    if not PHP_NAME_PATTERN.search(lower):
        return False
    if SHELL_NAME_PATTERN.search(lower):
        return True
    excluded = (
        "/wp-login.php", "/wp-cron.php", "/wp-admin/admin-ajax.php",
        "/xmlrpc.php", "/index.php",
    )
    if lower in excluded:
        return False
    segments = [segment for segment in lower.split("/") if segment]
    return len(segments) >= 4 and any(
        prefix in lower for prefix in (
            "/wp-includes/", "/wp-content/uploads/", "/.well-known/",
            "/uploads/", "/images/",
        )
    )


def php_probe_path(path):
    """Return True for a PHP path useful in high-volume probe detection."""
    lower = path.lower()
    if not PHP_NAME_PATTERN.search(lower):
        return False
    return lower not in (
        "/wp-login.php", "/wp-cron.php", "/wp-admin/admin-ajax.php",
        "/xmlrpc.php", "/index.php",
    )


def analyze_logs(items):
    """Parse access logs and return findings, timeline events, and statistics."""
    records = []
    source_ids = []
    stats = {"log_lines": 0, "parsed_log_lines": 0, "malformed_log_lines": 0}
    seen_content = set()
    duplicates = 0
    for item in items:
        lower = item.name.lower()
        if not is_access_log_name(lower):
            continue
        if item.sha256 in seen_content:
            duplicates += 1
            continue
        seen_content.add(item.sha256)
        source_ids.append(item.reference)
        with item.open() as handle:
            for _, raw_line, oversized in iter_bounded_lines(handle):
                stats["log_lines"] += 1
                if oversized:
                    stats["malformed_log_lines"] += 1
                    continue
                match = LOG_PATTERN.match(raw_line)
                if not match:
                    stats["malformed_log_lines"] += 1
                    continue
                try:
                    timestamp = parse_log_time(
                        match.group("time").decode("ascii", errors="strict")
                    )
                    target = match.group("target").decode("utf-8", errors="replace")
                    parsed = urlsplit(target)
                    path = parsed.path or "/"
                    size_raw = match.group("size")
                    size = 0 if size_raw == b"-" else int(size_raw)
                    record = {
                        "timestamp": timestamp,
                        "ip": match.group("ip").decode("ascii", errors="replace"),
                        "method": match.group("method").decode("ascii"),
                        "target": target,
                        "path": path,
                        "query": parsed.query,
                        "status": int(match.group("status")),
                        "size": size,
                        "source": item.reference,
                    }
                except (ValueError, UnicodeError):
                    stats["malformed_log_lines"] += 1
                    continue
                records.append(record)
                stats["parsed_log_lines"] += 1

    findings = []
    events = []
    indicators = []
    if not records:
        return findings, events, indicators, stats, duplicates

    response_counts = Counter((row["status"], row["size"]) for row in records)
    dominant_response, dominant_count = response_counts.most_common(1)[0]
    dominant_ratio = dominant_count / len(records)
    baseline = dominant_response if dominant_ratio >= 0.25 else None

    login_attempts = defaultdict(list)
    php_probes = defaultdict(list)
    hidden_interactions = []
    artifact_requests = []
    for row in records:
        lower_path = row["path"].lower()
        if lower_path == "/wp-login.php" and row["method"] == "POST":
            login_attempts[row["ip"]].append(row)
        if php_probe_path(row["path"]):
            php_probes[row["ip"]].append(row)
        if suspicious_php_path(row["path"]):
            nonbaseline = baseline is None or (row["status"], row["size"]) != baseline
            if (
                200 <= row["status"] < 300
                and nonbaseline
                and (row["method"] == "POST" or bool(row["query"]))
            ):
                hidden_interactions.append(row)
        if SHELL_NAME_PATTERN.search(lower_path):
            artifact_requests.append(row)

    brute_sources = []
    for ip_address, attempts in login_attempts.items():
        if len(attempts) < 20:
            continue
        attempts.sort(key=lambda item: item["timestamp"])
        brute_sources.append(ip_address)
        events.append({
            "timestamp": attempts[0]["timestamp"],
            "timestamp_basis": "Apache access log",
            "category": "Credential Access",
            "source_ip": ip_address,
            "action": "Automated POST requests to /wp-login.php",
            "outcome": "Attempted; no successful login is established by access logs",
            "confidence": "High",
            "summary": (
                str(len(attempts)) + " login POST requests were recorded between " +
                attempts[0]["timestamp"].isoformat() + " and " +
                attempts[-1]["timestamp"].isoformat() + "."
            ),
            "evidence_refs": sorted({row["source"] for row in attempts}),
        })
        indicators.append({
            "type": "IPv4",
            "value": ip_address,
            "context": "High-volume WordPress login attempts",
            "confidence": "High",
        })
    if brute_sources:
        total = sum(len(login_attempts[ip]) for ip in brute_sources)
        findings.append(finding(
            "Automated WordPress login attacks",
            "Medium", "High", "Credential Access",
            str(total) + " POST requests to /wp-login.php came from " +
            str(len(brute_sources)) + " source IP address(es).",
            [
                "Sources: " + ", ".join(sorted(brute_sources)),
                "Access logs do not prove that authentication succeeded.",
            ],
            source_ids,
            "Sustained password guessing can compromise weak or reused credentials.",
            "Reset exposed credentials, enforce MFA, review successful login and session "
            "records, and rate-limit or block abusive sources.",
        ))

    scanner_sources = []
    for ip_address, probes in php_probes.items():
        distinct = {row["path"].lower() for row in probes}
        if len(probes) < 50 and len(distinct) < 20:
            continue
        probes.sort(key=lambda item: item["timestamp"])
        scanner_sources.append((ip_address, len(probes), len(distinct)))
        events.append({
            "timestamp": probes[0]["timestamp"],
            "timestamp_basis": "Apache access log",
            "category": "Discovery",
            "source_ip": ip_address,
            "action": "High-volume probing for PHP shells and uploaders",
            "outcome": "Reconnaissance observed; individual 200 responses may be soft 404s",
            "confidence": "High",
            "summary": (
                str(len(probes)) + " requests covered " + str(len(distinct)) +
                " distinct suspicious PHP paths."
            ),
            "evidence_refs": sorted({row["source"] for row in probes}),
        })
        indicators.append({
            "type": "IPv4",
            "value": ip_address,
            "context": "High-volume PHP shell discovery",
            "confidence": "High",
        })
    if scanner_sources:
        evidence = [
            ip + ": " + str(total) + " requests, " + str(distinct) + " distinct paths"
            for ip, total, distinct in sorted(
                scanner_sources, key=lambda item: item[1], reverse=True
            )[:10]
        ]
        if baseline:
            evidence.append(
                "Dominant response baseline: HTTP " + str(baseline[0]) + " with " +
                str(baseline[1]) + " bytes (" +
                str(round(dominant_ratio * 100, 1)) + "% of parsed requests)."
            )
        findings.append(finding(
            "High-volume web-shell discovery activity",
            "Low", "High", "Reconnaissance",
            "Multiple sources probed many PHP filenames associated with shells, "
            "uploaders, and compromised websites.",
            evidence,
            source_ids,
            "The activity shows the site was being actively searched for known or "
            "previously planted malicious files.",
            "Block abusive sources where appropriate, retain logs, and inspect every "
            "unexpected executable file under the web root.",
        ))

    if hidden_interactions:
        hidden_interactions.sort(key=lambda item: item["timestamp"])
        evidence = []
        for row in hidden_interactions[:20]:
            target = row["path"] + ("?" + row["query"] if row["query"] else "")
            evidence.append(
                row["timestamp"].isoformat() + " " + row["ip"] + " " +
                row["method"] + " " + target + " -> " +
                str(row["status"]) + " (" + str(row["size"]) + " bytes)"
            )
            events.append({
                "timestamp": row["timestamp"],
                "timestamp_basis": "Apache access log",
                "category": "Web Shell",
                "source_ip": row["ip"],
                "action": row["method"] + " request to hidden PHP path",
                "outcome": "Observed interaction with a nonbaseline 2xx response",
                "confidence": "High",
                "summary": row["path"],
                "evidence_refs": [row["source"]],
            })
            indicators.append({
                "type": "URL path",
                "value": row["path"],
                "context": "Likely hidden PHP backdoor interaction",
                "confidence": "High",
            })
        findings.append(finding(
            "Likely interaction with a hidden PHP backdoor",
            "Critical", "High", "Execution",
            "POST or control-query requests reached suspicious deep PHP paths and "
            "received successful responses that differed from the site's dominant "
            "response baseline.",
            evidence,
            [row["source"] for row in hidden_interactions],
            "A working server-side backdoor can permit arbitrary code execution, data "
            "theft, persistence, and further malware deployment.",
            "Isolate the host, preserve a forensic image, rotate all secrets from a "
            "known-clean system, rebuild from trusted sources, and investigate adjacent "
            "hosts and accounts.",
        ))

    failed_x = [
        row for row in artifact_requests
        if row["path"].lower().endswith("/x.php") and row["status"] == 404
    ]
    if failed_x:
        row = sorted(failed_x, key=lambda item: item["timestamp"])[0]
        events.append({
            "timestamp": row["timestamp"],
            "timestamp_basis": "Apache access log",
            "category": "Web Shell",
            "source_ip": row["ip"],
            "action": "Request to /x.php",
            "outcome": "HTTP 404; execution is not established",
            "confidence": "High",
            "summary": "The supplied x.php artifact was not available at this URL then.",
            "evidence_refs": [row["source"]],
        })
    return findings, events, indicators, stats, duplicates


def analyze_auth_logs(items, timezone_text=""):
    """Analyze Linux authentication logs for SSH and account activity."""
    failed = defaultdict(list)
    accepted = []
    created_users = []
    source_ids = []
    seen_content = set()
    duplicates = 0
    stats = {
        "auth_log_lines": 0,
        "parsed_auth_log_lines": 0,
        "malformed_auth_log_lines": 0,
    }
    for item in items:
        if not is_auth_log_name(item.name):
            continue
        if item.sha256 in seen_content:
            duplicates += 1
            continue
        seen_content.add(item.sha256)
        source_ids.append(item.reference)
        with item.open() as handle:
            for line_number, raw_line, oversized in iter_bounded_lines(handle):
                stats["auth_log_lines"] += 1
                if oversized:
                    stats["malformed_auth_log_lines"] += 1
                    continue
                line = raw_line.decode("utf-8", errors="replace").strip()
                timestamp, basis = parse_auth_time(line, item, timezone_text)
                failed_match = AUTH_FAILED_PATTERN.search(line)
                accepted_match = AUTH_ACCEPTED_PATTERN.search(line)
                useradd_match = AUTH_USERADD_PATTERN.search(line)
                if not (failed_match or accepted_match or useradd_match):
                    continue
                if timestamp is None:
                    stats["malformed_auth_log_lines"] += 1
                    continue
                event = {
                    "timestamp": timestamp,
                    "basis": basis,
                    "source": item.reference,
                    "line": line_number,
                }
                if failed_match:
                    event.update(failed_match.groupdict())
                    failed[event["ip"]].append(event)
                elif accepted_match:
                    event.update(accepted_match.groupdict())
                    accepted.append(event)
                elif useradd_match:
                    event.update(useradd_match.groupdict())
                    created_users.append(event)
                stats["parsed_auth_log_lines"] += 1

    findings = []
    events = []
    indicators = []
    brute_sources = []
    for ip_address, attempts in failed.items():
        if len(attempts) < 20:
            continue
        attempts.sort(key=lambda item: item["timestamp"])
        brute_sources.append((ip_address, attempts))
        events.append({
            "timestamp": attempts[0]["timestamp"],
            "timestamp_basis": attempts[0]["basis"],
            "category": "Credential Access",
            "source_ip": ip_address,
            "action": "High-volume failed SSH authentication",
            "outcome": "Attempted; successful authentication is not established",
            "confidence": "High",
            "summary": (
                str(len(attempts)) + " failed SSH logins were recorded between " +
                attempts[0]["timestamp"].isoformat() + " and " +
                attempts[-1]["timestamp"].isoformat() + "."
            ),
            "evidence_refs": sorted({item["source"] for item in attempts}),
        })
        indicators.append({
            "type": "IP address",
            "value": ip_address,
            "context": "High-volume failed SSH authentication",
            "confidence": "High",
        })
    if brute_sources:
        findings.append(finding(
            "Automated SSH authentication attacks",
            "Medium", "High", "Credential Access",
            str(sum(len(items) for _, items in brute_sources)) +
            " failed SSH authentication events came from " +
            str(len(brute_sources)) + " high-volume source(s).",
            [
                ip + ": " + str(len(attempts)) + " failed authentication events"
                for ip, attempts in sorted(
                    brute_sources, key=lambda item: len(item[1]), reverse=True
                )[:20]
            ],
            source_ids,
            "Password guessing can compromise weak, reused, or exposed credentials.",
            "Validate exposed accounts, rotate affected credentials, enforce key-based "
            "access and MFA where supported, and restrict administrative network access.",
        ))

    suspicious_successes = []
    for event_number, event in enumerate(
        sorted(accepted, key=lambda item: item["timestamp"]), start=1
    ):
        prior_failures = [
            item for item in failed.get(event["ip"], [])
            if item["timestamp"] <= event["timestamp"]
        ]
        suspicious = event["user"] == "root" or len(prior_failures) >= 5
        if event_number <= 200:
            events.append({
                "timestamp": event["timestamp"],
                "timestamp_basis": event["basis"],
                "category": "Authentication",
                "source_ip": event["ip"],
                "action": "Successful SSH authentication for " + event["user"],
                "outcome": (
                    "Accepted " + event["method"] +
                    "; authorization not determined"
                ),
                "confidence": "Confirmed",
                "summary": (
                    "Authentication-log event at line " + str(event["line"]) +
                    (" followed " + str(len(prior_failures)) + " earlier failures"
                     if prior_failures else "")
                ),
                "evidence_refs": [event["source"]],
            })
        if suspicious:
            suspicious_successes.append((event, len(prior_failures)))
            indicators.append({
                "type": "IP address",
                "value": event["ip"],
                "context": "Successful SSH authentication requiring validation",
                "confidence": "High",
            })
    if suspicious_successes:
        findings.append(finding(
            "Successful SSH authentication requires validation",
            "High", "High", "Initial Access",
            "Authentication logs contain root access or successful SSH authentication "
            "from a source that generated repeated prior failures.",
            [
                item["timestamp"].isoformat() + " " + item["ip"] + " -> " +
                item["user"] + " via " + item["method"] + "; prior failures: " +
                str(prior_failures)
                for item, prior_failures in suspicious_successes[:30]
            ],
            [item["source"] for item, _ in suspicious_successes],
            "An unauthorized successful remote login can provide direct server access.",
            "Confirm each event with the system owner, review session and command "
            "history, rotate affected credentials, and investigate persistence.",
        ))

    if created_users:
        for event in created_users[:50]:
            events.append({
                "timestamp": event["timestamp"],
                "timestamp_basis": event["basis"],
                "category": "Persistence",
                "source_ip": "",
                "action": "Local account creation recorded",
                "outcome": "User " + event["user"] + " created; authorization unknown",
                "confidence": "Confirmed",
                "summary": "Authentication-log event at line " + str(event["line"]),
                "evidence_refs": [event["source"]],
            })
        findings.append(finding(
            "Local account creation requires validation",
            "High", "Medium", "Persistence",
            "Authentication logs record local account creation during the supplied "
            "evidence period.",
            [
                item["timestamp"].isoformat() + " user " + item["user"]
                for item in created_users[:30]
            ],
            [item["source"] for item in created_users],
            "An unauthorized local account can provide persistent server access.",
            "Validate each account with change records and remove unauthorized accounts "
            "only after preserving evidence and identifying dependent access.",
        ))
    return findings, events, indicators, stats, duplicates


def normalized_evidence_path(name):
    """Return a slash-normalized evidence path without a leading dot or slash."""
    return name.replace("\\", "/").lstrip("./")


def analyze_wordpress_acquisition(items):
    """Inventory a supplied WordPress project and flag executable uploads."""
    paths = []
    wordpress_files = 0
    plugins = set()
    themes = set()
    upload_executables = []
    version = ""
    version_source = ""
    php_files = 0
    for item in items:
        path = normalized_evidence_path(item.name)
        lower = path.lower()
        padded = "/" + lower.strip("/") + "/"
        paths.append((item, lower, padded))
        basename = lower.rsplit("/", 1)[-1]
        wordpress_related = (
            "/wp-admin/" in padded or
            "/wp-includes/" in padded or
            "/wp-content/" in padded or
            basename == "wp-config.php" or
            basename in {
                "index.php", "license.txt", "readme.html", "xmlrpc.php",
                "wp-activate.php", "wp-blog-header.php", "wp-comments-post.php",
                "wp-config-sample.php", "wp-cron.php", "wp-links-opml.php",
                "wp-load.php", "wp-login.php", "wp-mail.php",
                "wp-settings.php", "wp-signup.php", "wp-trackback.php",
            }
        )
        if wordpress_related:
            wordpress_files += 1
        if wordpress_related and lower.endswith((".php", ".phtml", ".php5")):
            php_files += 1
        plugin_match = re.search(r"(?:^|/)wp-content/plugins/([^/]+)", lower)
        if plugin_match:
            plugins.add(plugin_match.group(1))
        theme_match = re.search(r"(?:^|/)wp-content/themes/([^/]+)", lower)
        if theme_match:
            themes.add(theme_match.group(1))
        if (
            "/wp-content/uploads/" in padded and
            lower.endswith((".php", ".phtml", ".php5"))
        ):
            upload_executables.append(item)
        if lower.endswith("wp-includes/version.php") and not version:
            with item.open() as handle:
                text = static_excerpt(read_bounded(handle, MAX_STATIC_BYTES))
            match = re.search(
                r"\$wp_version\s*=\s*['\"](?P<version>[0-9][^'\"]*)['\"]",
                text,
            )
            if match:
                version = match.group("version")[:80]
                version_source = item.reference

    has_admin = any("/wp-admin/" in padded for _, _, padded in paths)
    has_includes = any("/wp-includes/" in padded for _, _, padded in paths)
    has_content = any("/wp-content/" in padded for _, _, padded in paths)
    has_config = any(lower.endswith("wp-config.php") for _, lower, _ in paths)
    detected = has_admin or has_includes or has_content or has_config
    inventory = {
        "detected": detected,
        "files_total": wordpress_files if detected else 0,
        "php_files": php_files if detected else 0,
        "core_present": has_admin and has_includes,
        "wp_admin_present": has_admin,
        "wp_includes_present": has_includes,
        "wp_content_present": has_content,
        "wp_config_present": has_config,
        "version": version,
        "version_source": version_source,
        "plugins": sorted(plugins),
        "themes": sorted(themes),
        "upload_executables": [
            {
                "path": item.name,
                "sha256": item.sha256,
                "source_id": item.reference,
            }
            for item in upload_executables[:100]
        ],
    }
    findings = []
    if upload_executables:
        findings.append(finding(
            "Executable PHP files present in WordPress uploads",
            "High", "Medium", "Persistence",
            str(len(upload_executables)) +
            " PHP-capable file(s) were found below wp-content/uploads. Location "
            "alone does not prove malicious intent, so each file requires review.",
            [
                item.name + " [" + item.sha256 + "]"
                for item in upload_executables[:50]
            ],
            [item.reference for item in upload_executables],
            "Executable files in a public upload directory are a common persistence "
            "and web-shell location.",
            "Compare every file with a trusted baseline, review ownership and access "
            "logs, quarantine confirmed malicious files after preserving evidence, "
            "and block script execution in upload directories.",
        ))
    return inventory, findings


def static_excerpt(data):
    """Decode a bounded amount of evidence for static marker matching."""
    return data[:MAX_STATIC_BYTES].decode("utf-8", errors="replace")


def analyze_server_files(items):
    """Classify PHP and server configuration artifacts without executing them."""
    malicious = []
    timeline = []
    indicators = []
    for item in items:
        lower = item.name.lower()
        if not (
            lower.endswith((".php", ".phtml", ".php5", "/.htaccess", "php.ini"))
            or lower.endswith(".htaccess")
        ):
            continue
        with item.open() as handle:
            data = read_bounded(handle, MAX_STATIC_BYTES)
        text = static_excerpt(data)
        markers = []
        classification = ""
        if "AnonGhost" in text and (
            "shell_exec" in text or "passthru" in text or "system(" in text
        ):
            classification = "interactive PHP web shell"
            markers = ["AnonGhost branding", "command-execution functions"]
        elif "move_uploaded_file" in text and "$_FILES" in text:
            classification = "unauthenticated PHP file uploader"
            markers = ["file upload input", "move_uploaded_file"]
        elif (
            "gzuncompress" in text and "eval" in text
        ) or ("__FILE__" in text and "eval" in text and data.count(b"\x00") > 0):
            classification = "obfuscated PHP loader"
            markers = ["runtime decompression", "dynamic evaluation"]
        elif lower.endswith("php.ini") and (
            "disable_functions = NONE" in text or "shell_exec = ON" in text
        ):
            classification = "execution-enabling PHP configuration"
            markers = ["disabled function restrictions", "shell execution enabled"]
        elif lower.endswith(".htaccess") and "Allow From All" in text and "php" in text:
            classification = "public-access rule for executable files"
            markers = ["Allow From All", "PHP included in FilesMatch"]
        elif data.count(b"\x00") > 20 and b"<?php" in data[:1024]:
            classification = "binary-packed PHP payload"
            markers = ["PHP header", "high binary-byte content"]
        if not classification:
            continue
        malicious.append((item, classification, markers))
        timeline.append({
            "timestamp": datetime.fromisoformat(
                item.modified_at.replace("Z", "+00:00")
            ),
            "timestamp_basis": (
                "Evidence filesystem modification time; this value can be copied "
                "or altered and is not proof of creation time"
            ),
            "category": "Persistence",
            "source_ip": "",
            "action": "Malicious or security-weakening server artifact present",
            "outcome": classification,
            "confidence": "High",
            "summary": item.name,
            "evidence_refs": [item.reference],
        })
        indicators.extend([
            {
                "type": "SHA-256",
                "value": item.sha256,
                "context": item.name + " - " + classification,
                "confidence": "High",
            },
            {
                "type": "File path",
                "value": item.name,
                "context": classification,
                "confidence": "High",
            },
        ])
    findings = []
    strong_classes = {
        "interactive PHP web shell",
        "unauthenticated PHP file uploader",
        "obfuscated PHP loader",
        "binary-packed PHP payload",
    }
    strong = [
        artifact for artifact in malicious if artifact[1] in strong_classes
    ]
    if malicious:
        evidence = [
            item.name + " [" + item.sha256 + "]: " + classification +
            " (" + ", ".join(markers) + ")"
            for item, classification, markers in malicious
        ]
        findings.append(finding(
            (
                "Malicious server-side artifacts supplied for analysis"
                if strong else "Suspicious server configuration artifacts"
            ),
            "Critical" if strong else "High",
            "Confirmed" if strong else "Medium",
            "Malware" if strong else "Security Configuration",
            (
                "Static analysis identified executable web-shell, uploader, loader, "
                "or related security-weakening configuration behavior. No supplied "
                "code was executed."
                if strong else
                "Static analysis identified configuration that exposes executable "
                "files or weakens PHP execution restrictions."
            ),
            evidence,
            [item.reference for item, _, _ in malicious],
            (
                "These capabilities support arbitrary command execution, malware "
                "upload, persistent access, and concealment."
                if strong else
                "The configuration can make executable payloads publicly reachable "
                "or remove safeguards around command execution."
            ),
            (
                "Do not clean only the named files. Isolate and rebuild the application "
                "from trusted media, compare the entire web root with known-good "
                "sources, rotate credentials and keys, and preserve originals for "
                "investigation."
                if strong else
                "Confirm whether the configuration is authorized, restore hardened "
                "PHP and web-server settings, and inspect nearby executable files."
            ),
        ))
    return findings, timeline, indicators


def analyze_sql(items):
    """Search SQL dumps conservatively for high-confidence injection indicators."""
    sql_lines = 0
    suspicious = []
    source_ids = []
    patterns = (
        re.compile(r"(?i)<script[^>]*>[^<]{0,300}(?:eval|atob|document\.write)\s*\("),
        re.compile(r"(?i)javascript\s*:[^,]{0,300}"),
        re.compile(r"(?i)<iframe[^>]+(?:display\s*:\s*none|width\s*=\s*[\"']?0)"),
        re.compile(r"(?i)(?:AnonGhost|FilesMan|WSO(?:\s|Shell)|move_uploaded_file\s*\()"),
        re.compile(r"(?i)<\?php[^\\n]{0,300}(?:eval|base64_decode|shell_exec|system)\s*\("),
    )
    for item in items:
        if not item.name.lower().endswith((".sql", ".sql.txt")):
            continue
        source_ids.append(item.reference)
        with item.open() as handle:
            for line_number, raw_line, _ in iter_bounded_lines(handle):
                sql_lines += 1
                text = raw_line.decode("utf-8", errors="replace")
                if any(pattern.search(text) for pattern in patterns):
                    excerpt = re.sub(r"\s+", " ", redact(text)).strip()[:240]
                    suspicious.append(
                        item.name + ":" + str(line_number) + ": " + excerpt
                    )
                    if len(suspicious) >= 30:
                        break
    findings = []
    if suspicious:
        findings.append(finding(
            "Suspicious executable content in database dump",
            "High", "Medium", "Database Integrity",
            "The SQL dump contains patterns associated with stored script injection "
            "or server-side payloads. Each match requires manual context review.",
            suspicious,
            source_ids,
            "Stored payloads can execute in visitor or administrator browsers and may "
            "reinfect cleaned application files.",
            "Review the referenced records in an isolated copy, compare against a "
            "known-good backup, remove unauthorized content, and identify the write path.",
        ))
    return findings, sql_lines, bool(suspicious)


def build_evidence_coverage(items, wordpress):
    """Summarize which core evidence areas were supplied for analysis."""
    access_items = [item for item in items if is_access_log_name(item.name)]
    auth_items = [item for item in items if is_auth_log_name(item.name)]
    sql_items = [
        item for item in items
        if item.name.lower().endswith((".sql", ".sql.txt"))
    ]
    return [
        {
            "area": "Web access logs",
            "status": "analyzed" if access_items else "not-provided",
            "items": len(access_items),
            "notes": "Apache combined-style records are supported.",
        },
        {
            "area": "Authentication logs",
            "status": "analyzed" if auth_items else "not-provided",
            "items": len(auth_items),
            "notes": "Linux SSH and local account events are supported.",
        },
        {
            "area": "SQL database dump",
            "status": "analyzed" if sql_items else "not-provided",
            "items": len(sql_items),
            "notes": "Static high-confidence content patterns are reviewed.",
        },
        {
            "area": "WordPress core",
            "status": (
                "analyzed" if wordpress["core_present"] else
                "partial" if (
                    wordpress["wp_admin_present"] or
                    wordpress["wp_includes_present"]
                ) else "not-provided"
            ),
            "items": (
                int(wordpress["wp_admin_present"]) +
                int(wordpress["wp_includes_present"])
            ),
            "notes": "Presence is inventoried; trusted checksum comparison is manual.",
        },
        {
            "area": "WordPress content",
            "status": (
                "analyzed" if wordpress["wp_content_present"] else "not-provided"
            ),
            "items": len(wordpress["plugins"]) + len(wordpress["themes"]),
            "notes": "Plugins, themes, uploads, and PHP artifacts are inventoried.",
        },
        {
            "area": "WordPress configuration",
            "status": (
                "analyzed" if wordpress["wp_config_present"] else "not-provided"
            ),
            "items": int(wordpress["wp_config_present"]),
            "notes": "Presence is recorded; secrets are not reproduced in the report.",
        },
    ]


def build_response_lifecycle(incident_state, originals_preserved):
    """Record automated and operator-owned incident-response phase status."""
    reached = {
        "unknown": 0,
        "active": 0,
        "contained": 1,
        "eradicated": 2,
        "recovered": 3,
    }.get(incident_state, 0)
    return [
        {
            "phase": "Preparation and evidence preservation",
            "status": "recorded" if originals_preserved else "needs-validation",
            "owner": "Incident lead and evidence custodian",
            "notes": (
                "Operator confirmed separate preservation of originals."
                if originals_preserved else
                "Separate preservation of original evidence was not confirmed."
            ),
        },
        {
            "phase": "Detection and analysis",
            "status": "automated-draft",
            "owner": "Incident analyst",
            "notes": "Tool output requires evidence-based analyst validation.",
        },
        {
            "phase": "Containment",
            "status": "operator-recorded" if reached >= 1 else "not-recorded",
            "owner": "System owner and incident lead",
            "notes": "Technical analysis does not perform containment.",
        },
        {
            "phase": "Eradication",
            "status": "operator-recorded" if reached >= 2 else "not-recorded",
            "owner": "System owner",
            "notes": "Removal and trusted rebuild must be independently verified.",
        },
        {
            "phase": "Recovery",
            "status": "operator-recorded" if reached >= 3 else "not-recorded",
            "owner": "System owner and business owner",
            "notes": "Service restoration and monitoring require owner approval.",
        },
        {
            "phase": "Post-incident improvement",
            "status": "pending",
            "owner": "Incident lead and service owner",
            "notes": "Complete a lessons-learned review after recovery.",
        },
    ]


def build_follow_up(compromise, incident_state, coverage):
    """Return essential human actions that remain after automated analysis."""
    actions = [
        "Validate every High and Critical finding against original evidence and "
        "document false positives or analyst adjustments.",
        "Correlate access, authentication, database, and filesystem timestamps in "
        "one normalized timeline while retaining each timestamp basis.",
        "Compare WordPress core, plugins, and themes with trusted vendor packages "
        "or known-good backups before declaring the application clean.",
        "Review legal, contractual, insurance, law-enforcement, and CISA reporting "
        "obligations with the client's authorized decision-makers.",
    ]
    missing = [
        item["area"] for item in coverage if item["status"] != "analyzed"
    ]
    if missing:
        actions.insert(
            0,
            "Obtain or document the absence of: " + ", ".join(missing) + ".",
        )
    if compromise in ("confirmed", "likely") and incident_state in ("unknown", "active"):
        actions.insert(
            0,
            "Contain affected systems and accounts using the approved incident plan; "
            "preserve volatile and persistent evidence before destructive cleanup.",
        )
    actions.append(
        "After eradication, restore from trusted sources, rotate exposed secrets from "
        "a known-clean system, monitor for recurrence, and record lessons learned."
    )
    return actions


def highest_severity(findings):
    """Return the highest finding severity, or Info when no findings exist."""
    order = ("Critical", "High", "Medium", "Low", "Info")
    present = {item["severity"] for item in findings}
    return next((severity for severity in order if severity in present), "Info")


def normalize_events(events):
    """Sort timeline events and serialize datetimes."""
    events.sort(key=lambda item: item["timestamp"])
    normalized = []
    for number, event in enumerate(events, start=1):
        item = dict(event)
        timestamp = item["timestamp"]
        if isinstance(timestamp, datetime):
            item["timestamp"] = timestamp.isoformat()
        item["id"] = "TL-" + str(number).zfill(4)
        normalized.append(item)
    return normalized


def deduplicate_indicators(indicators):
    """Return unique indicators in stable order."""
    seen = set()
    result = []
    for indicator in indicators:
        key = (indicator["type"], indicator["value"], indicator["context"])
        if key not in seen:
            seen.add(key)
            result.append(indicator)
    return result


def run_forensics(source, case_id, site="", authorization_reference="",
                  operator="", client="", received_at="", received_from="",
                  collection_method="", source_timezone="",
                  originals_preserved=False, incident_state="unknown"):
    """Analyze an evidence file or folder and return a forensic result."""
    started_at = utc_now()
    result = {
        "artifact_type": "forensics",
        "schema_version": FORENSICS_SCHEMA_VERSION,
        "tool_version": __version__,
        "case_id": case_id or str(uuid.uuid4()),
        "status": "complete",
        "site": site,
        "started_at": started_at,
        "finished_at": started_at,
        "authorization": {
            "reference": authorization_reference,
            "operator": operator,
            "client": client,
        },
        "evidence_intake": {
            "received_at": received_at,
            "received_from": received_from,
            "collection_method": collection_method,
            "source_timezone": source_timezone,
            "originals_preserved": originals_preserved,
        },
        "scope": {
            "source": str(Path(source).resolve()),
            "mode": "offline-static-evidence-analysis",
            "archive_limits": {
                "member_bytes": MAX_MEMBER_BYTES,
                "total_expanded_bytes": MAX_TOTAL_ARCHIVE_BYTES,
                "members": MAX_ARCHIVE_MEMBERS,
            },
        },
        "sources": [],
        "coverage": [],
        "wordpress": {
            "detected": False,
            "files_total": 0,
            "php_files": 0,
            "core_present": False,
            "wp_admin_present": False,
            "wp_includes_present": False,
            "wp_content_present": False,
            "wp_config_present": False,
            "version": "",
            "version_source": "",
            "plugins": [],
            "themes": [],
            "upload_executables": [],
        },
        "findings": [],
        "timeline": [],
        "assessment": {
            "compromise_status": "undetermined",
            "initial_access": "undetermined",
            "database_injection": "undetermined",
            "technical_severity": "Info",
            "incident_state": incident_state,
            "business_impact": "Not assessed from supplied technical evidence.",
            "summary": "",
            "limitations": [],
        },
        "response_lifecycle": [],
        "required_follow_up": [],
        "methodology": METHODOLOGY,
        "indicators": [],
        "statistics": {},
        "errors": [],
    }
    try:
        manifests, items, errors = collect_evidence(source)
        result["sources"] = manifests
        result["errors"].extend(errors)

        log_findings, log_events, log_indicators, log_stats, duplicates = (
            analyze_logs(items)
        )
        auth_findings, auth_events, auth_indicators, auth_stats, auth_duplicates = (
            analyze_auth_logs(items, source_timezone)
        )
        wordpress, wordpress_findings = analyze_wordpress_acquisition(items)
        result["wordpress"] = wordpress
        result["coverage"] = build_evidence_coverage(items, wordpress)
        file_findings, file_events, file_indicators = analyze_server_files(items)
        sql_findings, sql_lines, sql_suspicious = analyze_sql(items)
        result["findings"] = (
            file_findings + wordpress_findings + log_findings +
            auth_findings + sql_findings
        )
        result["timeline"] = normalize_events(
            file_events + log_events + auth_events
        )
        result["indicators"] = deduplicate_indicators(
            file_indicators + log_indicators + auth_indicators
        )

        confirmed_malware = any(
            item["category"] == "Malware" and item["confidence"] == "Confirmed"
            for item in file_findings
        )
        compromise = "confirmed" if confirmed_malware else (
            "likely" if any(item["category"] == "Execution"
                            for item in log_findings) else "undetermined"
        )
        suspicious_auth = any(
            item["title"] == "Successful SSH authentication requires validation"
            for item in auth_findings
        )
        result["assessment"] = {
            "compromise_status": compromise,
            "initial_access": "possible" if suspicious_auth else "undetermined",
            "database_injection": "possible" if sql_suspicious else "not-found",
            "technical_severity": highest_severity(result["findings"]),
            "incident_state": incident_state,
            "business_impact": "Not assessed from supplied technical evidence.",
            "summary": (
                "Server compromise is confirmed by supplied malicious artifacts."
                if compromise == "confirmed" else
                "The supplied evidence does not independently confirm compromise."
            ),
            "limitations": [
                "The supplied access logs cover only a limited time window and may begin "
                "after initial access.",
                "HTTP access logs show requests and responses, not command output or "
                "successful authentication.",
                "Filesystem modification times can be copied, altered, or changed during "
                "evidence collection.",
                "No trusted WordPress core, plugin, or theme checksum comparison was "
                "performed; presence and static indicators are not proof of integrity.",
                (
                    "Traditional authentication-log years are inferred from evidence "
                    "modification time and the operator-supplied source timezone."
                    if auth_stats["parsed_auth_log_lines"] else
                    "No supported authentication events were parsed from the supplied "
                    "evidence."
                ),
                (
                    "No high-confidence stored script or PHP injection pattern was found "
                    "in the SQL dump; this is not proof that every record is clean."
                    if not sql_suspicious else
                    "SQL pattern matches require manual record-level validation."
                ),
            ],
        }
        result["response_lifecycle"] = build_response_lifecycle(
            incident_state, originals_preserved
        )
        result["required_follow_up"] = build_follow_up(
            compromise, incident_state, result["coverage"]
        )
        result["statistics"] = {
            "source_files": len(manifests),
            "archive_members": sum(len(item["members"]) for item in manifests),
            "duplicate_items": duplicates + auth_duplicates,
            "log_lines": log_stats["log_lines"],
            "parsed_log_lines": log_stats["parsed_log_lines"],
            "malformed_log_lines": log_stats["malformed_log_lines"],
            "auth_log_lines": auth_stats["auth_log_lines"],
            "parsed_auth_log_lines": auth_stats["parsed_auth_log_lines"],
            "malformed_auth_log_lines": auth_stats["malformed_auth_log_lines"],
            "sql_lines": sql_lines,
            "wordpress_files": wordpress["files_total"],
            "php_files": wordpress["php_files"],
            "findings_total": len(result["findings"]),
            "timeline_events": len(result["timeline"]),
        }
        if errors:
            result["status"] = "incomplete"
    except (OSError, ValueError) as error:
        result["status"] = "failed"
        result["errors"].append(str(error))
        result["statistics"] = {
            "source_files": len(result["sources"]),
            "archive_members": 0,
            "duplicate_items": 0,
            "log_lines": 0,
            "parsed_log_lines": 0,
            "malformed_log_lines": 0,
            "auth_log_lines": 0,
            "parsed_auth_log_lines": 0,
            "malformed_auth_log_lines": 0,
            "sql_lines": 0,
            "wordpress_files": 0,
            "php_files": 0,
            "findings_total": 0,
            "timeline_events": 0,
        }
    result["finished_at"] = utc_now()
    return result
