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
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from . import __version__

MAX_MEMBER_BYTES = 100 * 1024 * 1024
MAX_TOTAL_ARCHIVE_BYTES = 500 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5000
MAX_STATIC_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024

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
        if not (
            "accesslog" in lower or "access.log" in lower or
            "ssl_log" in lower or lower.endswith((".log", "_log"))
        ):
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
                  operator="", client=""):
    """Analyze an evidence file or folder and return a forensic result."""
    started_at = utc_now()
    result = {
        "artifact_type": "forensics",
        "schema_version": "1.0",
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
        "findings": [],
        "timeline": [],
        "assessment": {
            "compromise_status": "undetermined",
            "initial_access": "undetermined",
            "database_injection": "undetermined",
            "summary": "",
            "limitations": [],
        },
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
        file_findings, file_events, file_indicators = analyze_server_files(items)
        sql_findings, sql_lines, sql_suspicious = analyze_sql(items)
        result["findings"] = file_findings + log_findings + sql_findings
        result["timeline"] = normalize_events(file_events + log_events)
        result["indicators"] = deduplicate_indicators(
            file_indicators + log_indicators
        )

        confirmed_malware = any(
            item["category"] == "Malware" and item["confidence"] == "Confirmed"
            for item in file_findings
        )
        compromise = "confirmed" if confirmed_malware else (
            "likely" if any(item["category"] == "Execution"
                            for item in log_findings) else "undetermined"
        )
        result["assessment"] = {
            "compromise_status": compromise,
            "initial_access": "undetermined",
            "database_injection": "possible" if sql_suspicious else "not-found",
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
                (
                    "No high-confidence stored script or PHP injection pattern was found "
                    "in the SQL dump; this is not proof that every record is clean."
                    if not sql_suspicious else
                    "SQL pattern matches require manual record-level validation."
                ),
            ],
        }
        result["statistics"] = {
            "source_files": len(manifests),
            "archive_members": sum(len(item["members"]) for item in manifests),
            "duplicate_items": duplicates,
            "log_lines": log_stats["log_lines"],
            "parsed_log_lines": log_stats["parsed_log_lines"],
            "malformed_log_lines": log_stats["malformed_log_lines"],
            "sql_lines": sql_lines,
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
            "sql_lines": 0,
            "findings_total": 0,
            "timeline_events": 0,
        }
    result["finished_at"] = utc_now()
    return result
