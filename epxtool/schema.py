"""Validation rules for saved epxtool scan results.

The JSON schema is intentionally implemented with plain Python so the toolkit
keeps its zero-dependency installation.
"""

import re
import uuid
from datetime import datetime

from .findings import CONFIDENCE_LEVELS, SEVERITY_ORDER

SCHEMA_VERSION = "1.0"
SCAN_STATUSES = ("complete", "incomplete", "failed")
CHECK_STATUSES = ("completed", "partial", "failed", "skipped")


def require_type(container, key, expected_type, location="result"):
    """Return a required value or raise a useful validation error."""
    if key not in container:
        raise ValueError(location + " is missing field: " + key)
    value = container[key]
    if not isinstance(value, expected_type):
        raise ValueError(location + " field '" + key + "' has the wrong type")
    return value


def validate_timestamp(value, location):
    """Validate the UTC timestamp format emitted by the scanner."""
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(location + " is not a valid ISO-8601 timestamp") from error


ATTACK_ID_PATTERN = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")


def validate_attack(attack, location):
    """Validate the optional MITRE ATT&CK technique list on a finding."""
    if not isinstance(attack, list):
        raise ValueError(location + " field 'attack' must be a list")
    for number, technique in enumerate(attack, start=1):
        where = location + " attack technique " + str(number)
        if not isinstance(technique, dict):
            raise ValueError(where + " must be an object")
        for key in ("id", "name", "tactic", "url"):
            require_type(technique, key, str, where)
        if not ATTACK_ID_PATTERN.fullmatch(technique["id"]):
            raise ValueError(where + " has an invalid ATT&CK technique id")


def validate_result(result):
    """Raise ValueError when input is not a valid current scan result."""
    if not isinstance(result, dict):
        raise ValueError("the JSON root must be an object")

    schema_version = require_type(result, "schema_version", str)
    if schema_version != SCHEMA_VERSION:
        raise ValueError(
            "unsupported schema_version '" + schema_version +
            "' (expected " + SCHEMA_VERSION + ")"
        )

    for key in (
        "tool_version",
        "scan_id",
        "status",
        "target",
        "started_at",
        "finished_at",
    ):
        require_type(result, key, str)

    try:
        uuid.UUID(result["scan_id"])
    except ValueError as error:
        raise ValueError("result field 'scan_id' is not a valid UUID") from error
    validate_timestamp(result["started_at"], "result started_at")
    validate_timestamp(result["finished_at"], "result finished_at")

    if result["status"] not in SCAN_STATUSES:
        raise ValueError("result field 'status' has an unknown value")

    authorization = require_type(result, "authorization", dict)
    require_type(authorization, "confirmed", bool, "authorization")
    for key in ("reference", "operator", "client", "confirmed_at"):
        require_type(authorization, key, str, "authorization")
    if authorization["confirmed"]:
        if not authorization["reference"].strip():
            raise ValueError("confirmed authorization requires a reference")
        if not authorization["operator"].strip():
            raise ValueError("confirmed authorization requires an operator")
        validate_timestamp(
            authorization["confirmed_at"],
            "authorization confirmed_at",
        )
    if result["status"] == "complete" and not authorization["confirmed"]:
        raise ValueError("a complete scan requires confirmed authorization")

    scope = require_type(result, "scope", dict)
    for key in ("mode", "base_url", "hostname", "path"):
        require_type(scope, key, str, "scope")
    require_type(scope, "methods", list, "scope")
    selected_checks = require_type(scope, "selected_checks", list, "scope")

    settings = require_type(result, "settings", dict)
    require_type(settings, "timeout_seconds", (int, float), "settings")
    require_type(settings, "verify_tls", bool, "settings")
    require_type(settings, "delay_seconds", (int, float), "settings")
    require_type(settings, "max_requests", int, "settings")
    require_type(settings, "max_response_bytes", int, "settings")

    require_type(result, "info", dict)
    require_type(result, "errors", list)
    statistics = require_type(result, "statistics", dict)
    for key in (
        "requests_total",
        "network_requests",
        "request_errors",
        "bytes_received",
        "truncated_responses",
        "findings_total",
    ):
        require_type(statistics, key, int, "statistics")
    require_type(statistics, "duration_seconds", (int, float), "statistics")

    checks = require_type(result, "checks", list)
    check_ids = set()
    for number, check in enumerate(checks, start=1):
        location = "check " + str(number)
        if not isinstance(check, dict):
            raise ValueError(location + " must be an object")
        for key in ("id", "status", "started_at", "finished_at"):
            require_type(check, key, str, location)
        require_type(check, "findings_count", int, location)
        require_type(check, "request_ids", list, location)
        require_type(check, "errors", list, location)
        if check["status"] not in CHECK_STATUSES:
            raise ValueError(location + " has an unknown status")
        if check["id"] in check_ids:
            raise ValueError("duplicate check id: " + check["id"])
        check_ids.add(check["id"])
        if check["started_at"]:
            validate_timestamp(check["started_at"], location + " started_at")
        if check["finished_at"]:
            validate_timestamp(check["finished_at"], location + " finished_at")

    for check_id in selected_checks:
        if check_id not in check_ids:
            raise ValueError("scope references unknown check id: " + str(check_id))
    if result["status"] == "complete":
        for check in checks:
            if check["id"] in selected_checks and check["status"] != "completed":
                raise ValueError(
                    "complete scan has non-completed check: " + check["id"]
                )

    findings = require_type(result, "findings", list)
    finding_ids = set()
    finding_fields = (
        "id",
        "check_id",
        "category",
        "confidence",
        "title",
        "severity",
        "summary",
        "impact",
        "recommendation",
    )
    for number, finding in enumerate(findings, start=1):
        location = "finding " + str(number)
        if not isinstance(finding, dict):
            raise ValueError(location + " must be an object")
        for key in finding_fields:
            require_type(finding, key, str, location)
        require_type(finding, "evidence", list, location)
        require_type(finding, "request_ids", list, location)
        validate_attack(finding.get("attack", []), location)
        if finding["severity"] not in SEVERITY_ORDER:
            raise ValueError(location + " has an unknown severity")
        if finding["confidence"] not in CONFIDENCE_LEVELS:
            raise ValueError(location + " has an unknown confidence")
        if finding["id"] in finding_ids:
            raise ValueError("duplicate finding id: " + finding["id"])
        finding_ids.add(finding["id"])
        if finding["check_id"] not in check_ids:
            raise ValueError(location + " references an unknown check id")
        if not re.fullmatch(r"EPX-[A-F0-9]{10}", finding["id"]):
            raise ValueError(location + " has an invalid finding id")

    evidence = require_type(result, "evidence", dict)
    requests = require_type(evidence, "requests", list, "evidence")
    request_ids = set()
    for number, request in enumerate(requests, start=1):
        location = "request " + str(number)
        if not isinstance(request, dict):
            raise ValueError(location + " must be an object")
        for key in (
            "id",
            "timestamp",
            "method",
            "url",
            "final_url",
            "content_type",
            "sha256",
            "error",
        ):
            require_type(request, key, str, location)
        for key in ("status", "duration_ms", "bytes_read"):
            require_type(request, key, int, location)
        require_type(request, "truncated", bool, location)
        validate_timestamp(request["timestamp"], location + " timestamp")
        if request["id"] in request_ids:
            raise ValueError("duplicate request id: " + request["id"])
        request_ids.add(request["id"])
        if not re.fullmatch(r"REQ-[0-9]{4,}", request["id"]):
            raise ValueError(location + " has an invalid request id")
        if request["sha256"] and not re.fullmatch(
            r"[a-f0-9]{64}",
            request["sha256"],
        ):
            raise ValueError(location + " has an invalid SHA-256 value")

    for check in checks:
        for request_id in check["request_ids"]:
            if request_id not in request_ids:
                raise ValueError(
                    "check '" + check["id"] +
                    "' references unknown request id " + request_id
                )
    for finding in findings:
        for request_id in finding["request_ids"]:
            if request_id not in request_ids:
                raise ValueError(
                    "finding '" + finding["id"] +
                    "' references unknown request id " + request_id
                )

    if statistics["requests_total"] != len(requests):
        raise ValueError("statistics requests_total does not match evidence")
    if statistics["findings_total"] != len(findings):
        raise ValueError("statistics findings_total does not match findings")
    if statistics["network_requests"] > statistics["requests_total"]:
        raise ValueError("statistics network_requests exceeds requests_total")

    return result
