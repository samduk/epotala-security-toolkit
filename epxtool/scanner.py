"""
scanner.py
==========

This ties everything together. The function `run_scan()`:

  1. tidies up the target address
  2. gathers basic facts about the site (detect.collect_info)
  3. runs every check in checks.ALL_CHECKS
  4. collects all the findings into one big result dictionary
  5. returns that result

The result is a versioned JSON record containing authorization, scope, check
completion, findings, and a hash-only HTTP evidence trail.
"""

import hashlib
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from . import detect
from . import cve
from .checks import ALL_CHECKS
from .http_helper import HttpClient, MAX_RESPONSE_BYTES
from .schema import SCHEMA_VERSION

CVE_CHECK_ID = "cve-correlation"


def tidy_target(target):
    """Validate and normalize one HTTP(S) target address."""
    target = target.strip()
    if not target:
        raise ValueError("target cannot be empty")
    if any(character.isspace() for character in target):
        raise ValueError("target cannot contain spaces")

    lower_target = target.lower()
    if "://" in target and not (
        lower_target.startswith("http://") or lower_target.startswith("https://")
    ):
        raise ValueError("target must use http:// or https://")

    if not lower_target.startswith("http://") and not lower_target.startswith("https://"):
        target = "http://" + target

    parts = urlsplit(target)
    if parts.scheme not in ("http", "https"):
        raise ValueError("target must use http:// or https://")
    if not parts.hostname:
        raise ValueError("target must include a hostname")
    if parts.username or parts.password:
        raise ValueError("target must not include a username or password")
    if parts.query or parts.fragment:
        raise ValueError("put query strings in a check, not in the target address")

    try:
        parts.port
    except ValueError as error:
        raise ValueError("target has an invalid port") from error

    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), parts.netloc, path, "", ""))


def now_text():
    """Return the current time as text, e.g. 2026-06-14T10:00:00Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def empty_info(error_text=""):
    """Return the stable information shape used when discovery fails."""
    return {
        "server": "unknown",
        "reachable": False,
        "home_status": 0,
        "home_error": error_text,
        "is_wordpress": False,
        "wp_version": "",
        "components": {},
        "users": [],
        "home_final_url": "",
        "home_headers": {},
        "evidence_requests": {
            "home": [],
            "wp_version": [],
            "components": [],
            "users": [],
        },
    }


def stable_finding_id(check_id, title):
    """Return a deterministic identifier for the same finding type."""
    digest = hashlib.sha256((check_id + "\n" + title).encode("utf-8")).hexdigest()
    return "EPX-" + digest[:10].upper()


def check_record(check_id, status="skipped"):
    """Build one per-check execution record."""
    return {
        "id": check_id,
        "status": status,
        "started_at": "",
        "finished_at": "",
        "findings_count": 0,
        "request_ids": [],
        "errors": [],
    }


def normalize_authorization(authorization):
    """Return a complete authorization object for the saved result."""
    authorization = authorization or {}
    return {
        "confirmed": bool(authorization.get("confirmed", False)),
        "reference": str(authorization.get("reference", "")),
        "operator": str(authorization.get("operator", "")),
        "client": str(authorization.get("client", "")),
        "confirmed_at": str(authorization.get("confirmed_at", "")),
    }


def run_scan(
    target,
    timeout=10,
    verify_tls=True,
    only=None,
    log=None,
    authorization=None,
    delay=0.1,
    max_requests=100,
    max_response_bytes=MAX_RESPONSE_BYTES,
    cve_source=None,
    cve_api_key="",
):
    """Scan one website and return a result dictionary.

    Arguments:
      target      - the site address or host name
      timeout     - seconds to wait for each request
      verify_tls  - check HTTPS certificates? (set False for self-signed certs)
      only        - if given, a list of check ids to run (others are skipped)
      log         - a function to print progress (we default to printing nothing)
      authorization - operator/client authorization record
      delay       - minimum delay between requests
      max_requests - hard request budget for the scan
      max_response_bytes - maximum bytes read from one response
      cve_source  - optional vulnerability feed name (e.g. "wpscan") to enable
                    opt-in CVE correlation; this sends component names off-host
      cve_api_key - API key for the CVE source
    """
    if log is None:
        log = lambda message: None  # do nothing

    base_url = tidy_target(target)
    parts = urlsplit(base_url)
    cve_enabled = bool(cve_source)
    all_check_ids = [check_id for check_id, function in ALL_CHECKS]
    selected_checks = list(only) if only else list(all_check_ids)
    if cve_enabled and CVE_CHECK_ID not in selected_checks:
        selected_checks.append(CVE_CHECK_ID)
    started_monotonic = time.monotonic()

    client = HttpClient(
        base_url,
        timeout=timeout,
        verify_tls=verify_tls,
        delay=delay,
        max_requests=max_requests,
        max_response_bytes=max_response_bytes,
    )

    result = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "scan_id": str(uuid.uuid4()),
        "status": "incomplete",
        "target": base_url,
        "started_at": now_text(),
        "finished_at": "",
        "authorization": normalize_authorization(authorization),
        "scope": {
            "mode": "external-read-only",
            "base_url": base_url,
            "hostname": parts.hostname or "",
            "path": parts.path or "/",
            "methods": ["GET", "POST"],
            "selected_checks": selected_checks,
        },
        "settings": {
            "timeout_seconds": timeout,
            "verify_tls": verify_tls,
            "delay_seconds": delay,
            "max_requests": max_requests,
            "max_response_bytes": max_response_bytes,
            "cve_source": cve_source or "",
        },
        "info": {},
        "checks": [check_record("discovery", "skipped")] + [
            check_record(check_id, "skipped")
            for check_id in all_check_ids
        ] + ([check_record(CVE_CHECK_ID, "skipped")] if cve_enabled else []),
        "findings": [],
        "errors": [],
        "statistics": {},
        "evidence": {"requests": []},
    }
    if not result["authorization"]["confirmed"]:
        result["errors"].append(
            "authorization confirmation was not recorded for this scan"
        )

    # Step 1: gather basic facts about the site.
    log("[*] Gathering basic information ...")
    discovery = result["checks"][0]
    discovery["started_at"] = now_text()
    discovery_trace_start = len(client.trace)
    try:
        info = detect.collect_info(base_url, client)
    # Discovery is an extension boundary; preserve a failed result even if a
    # detector has an unexpected defect.
    except Exception as error:  # pylint: disable=broad-except
        message = "basic information gathering failed: " + str(error)
        result["info"] = empty_info(message)
        result["errors"].append(message)
        discovery["status"] = "failed"
        discovery["errors"].append(message)
        discovery["finished_at"] = now_text()
        discovery["request_ids"] = client.request_ids_since(discovery_trace_start)
        result["status"] = "failed"
        result["finished_at"] = now_text()
        finish_result(result, client, started_monotonic)
        log("    ! " + message)
        return result

    result["info"] = info
    discovery["finished_at"] = now_text()
    discovery["request_ids"] = client.request_ids_since(discovery_trace_start)
    discovery_request_errors = request_errors_since(
        client,
        discovery_trace_start,
    )
    if discovery_request_errors:
        discovery["status"] = "partial"
        discovery["errors"].extend(discovery_request_errors)
        result["errors"].extend(
            "discovery: " + error for error in discovery_request_errors
        )
    else:
        discovery["status"] = "completed"

    log("    server: " + info["server"] +
        "   wordpress: " + ("yes" if info["is_wordpress"] else "no"))

    if not info.get("reachable"):
        message = "target could not be reached"
        if info.get("home_error"):
            message = message + ": " + info["home_error"]
        result["errors"].append(message)
        discovery["status"] = "failed"
        discovery["errors"].append(message)
        result["status"] = "failed"
        result["finished_at"] = now_text()
        finish_result(result, client, started_monotonic)
        return result

    if not info.get("is_wordpress"):
        message = "WordPress was not detected, so WordPress-specific checks were skipped."
        result["errors"].append(message)
        result["status"] = "incomplete"
        result["finished_at"] = now_text()
        finish_result(result, client, started_monotonic)
        return result

    # Step 2: run each check, one at a time.
    records = {record["id"]: record for record in result["checks"]}
    for check_id, check_function in ALL_CHECKS:
        # If the user asked for only certain checks, skip the rest.
        record = records[check_id]
        if check_id not in selected_checks:
            continue

        log("[*] Running check: " + check_id)
        record["started_at"] = now_text()
        trace_start = len(client.trace)
        try:
            new_findings = check_function(base_url, info, client)
            request_ids = client.request_ids_since(trace_start)
            for finding in new_findings:
                finding["id"] = stable_finding_id(check_id, finding["title"])
                finding["check_id"] = check_id
                if not finding["request_ids"]:
                    finding["request_ids"] = request_ids
                result["findings"].append(finding)
            record["findings_count"] = len(new_findings)
            record["request_ids"] = request_ids
            request_errors = request_errors_since(client, trace_start)
            if request_errors:
                record["status"] = "partial"
                record["errors"].extend(request_errors)
                result["errors"].extend(
                    check_id + ": " + error for error in request_errors
                )
            else:
                record["status"] = "completed"
        except Exception as error:  # pylint: disable=broad-except
            # If a check crashes, record it but keep going with the others.
            message = check_id + " failed: " + str(error)
            result["errors"].append(message)
            record["status"] = "failed"
            record["errors"].append(str(error))
            record["request_ids"] = client.request_ids_since(trace_start)
            log("    ! " + message)
        record["finished_at"] = now_text()

    # Optional, opt-in step: correlate detected components against a vulnerability
    # feed. This is the only step that contacts a third party, so it is fully
    # separate from the target evidence trace and never crashes the scan.
    if cve_enabled:
        record = records[CVE_CHECK_ID]
        log("[*] Correlating components against " + cve_source + " ...")
        record["started_at"] = now_text()
        try:
            cve_findings, cve_errors = cve.correlate(
                info.get("wp_version", ""),
                info.get("components", {}),
                cve_api_key,
                source=cve_source,
                timeout=timeout,
                verify_tls=verify_tls,
            )
            for finding in cve_findings:
                finding["id"] = stable_finding_id(CVE_CHECK_ID, finding["title"])
                finding["check_id"] = CVE_CHECK_ID
                result["findings"].append(finding)
            record["findings_count"] = len(cve_findings)
            if cve_errors:
                record["status"] = "partial"
                record["errors"].extend(cve_errors)
                result["errors"].extend(
                    CVE_CHECK_ID + ": " + error for error in cve_errors
                )
            else:
                record["status"] = "completed"
        except Exception as error:  # pylint: disable=broad-except
            message = CVE_CHECK_ID + " failed: " + str(error)
            result["errors"].append(message)
            record["status"] = "failed"
            record["errors"].append(str(error))
            log("    ! " + message)
        record["finished_at"] = now_text()

    selected_records = [records[check_id] for check_id in selected_checks]
    if result["errors"] or any(
        record["status"] in ("partial", "failed") for record in selected_records
    ):
        result["status"] = "incomplete"
    else:
        result["status"] = "complete"
    result["finished_at"] = now_text()
    finish_result(result, client, started_monotonic)
    return result


def request_errors_since(client, start_index):
    """Return request error messages recorded after a trace index."""
    errors = []
    for item in client.trace[start_index:]:
        if item["error"]:
            errors.append(item["id"] + " " + item["error"])
    return errors


def finish_result(result, client, started_monotonic):
    """Attach final evidence and aggregate statistics to a result."""
    result["evidence"]["requests"] = list(client.trace)
    statistics = client.statistics()
    statistics["duration_seconds"] = round(
        time.monotonic() - started_monotonic,
        3,
    )
    statistics["findings_total"] = len(result["findings"])
    result["statistics"] = statistics
