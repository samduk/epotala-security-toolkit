"""Validation rules for saved epxtool forensic-analysis results."""

import re
from datetime import datetime

from .findings import CONFIDENCE_LEVELS, SEVERITY_ORDER
from .schema import require_type

FORENSICS_SCHEMA_VERSION = "1.1"
SUPPORTED_FORENSICS_SCHEMA_VERSIONS = ("1.0", "1.1")
FORENSICS_STATUSES = ("complete", "incomplete", "failed")
ASSESSMENT_STATES = ("confirmed", "likely", "possible", "not-found", "undetermined")
INCIDENT_STATES = ("unknown", "active", "contained", "eradicated", "recovered")
COVERAGE_STATES = ("analyzed", "partial", "not-provided")


def validate_timestamp(value, location, allow_empty=False):
    """Validate an ISO-8601 timestamp."""
    if allow_empty and not value:
        return
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(location + " is not a valid ISO-8601 timestamp") from error


def validate_forensics_result(result):
    """Raise ValueError when input is not a current forensic result."""
    if not isinstance(result, dict):
        raise ValueError("the JSON root must be an object")
    if require_type(result, "artifact_type", str) != "forensics":
        raise ValueError("artifact_type must be 'forensics'")
    schema_version = require_type(result, "schema_version", str)
    if schema_version not in SUPPORTED_FORENSICS_SCHEMA_VERSIONS:
        raise ValueError(
            "unsupported forensic schema_version (supported: " +
            ", ".join(SUPPORTED_FORENSICS_SCHEMA_VERSIONS) + ")"
        )

    for key in (
        "tool_version", "case_id", "status", "site", "started_at", "finished_at",
    ):
        require_type(result, key, str)
    if result["status"] not in FORENSICS_STATUSES:
        raise ValueError("result field 'status' has an unknown value")
    validate_timestamp(result["started_at"], "result started_at")
    validate_timestamp(result["finished_at"], "result finished_at")

    authorization = require_type(result, "authorization", dict)
    for key in ("reference", "operator", "client"):
        require_type(authorization, key, str, "authorization")

    if schema_version == "1.1":
        intake = require_type(result, "evidence_intake", dict)
        for key in (
            "received_at", "received_from", "collection_method", "source_timezone",
        ):
            require_type(intake, key, str, "evidence_intake")
        require_type(intake, "originals_preserved", bool, "evidence_intake")
        validate_timestamp(
            intake["received_at"], "evidence_intake received_at", allow_empty=True
        )

    scope = require_type(result, "scope", dict)
    for key in ("source", "mode"):
        require_type(scope, key, str, "scope")
    require_type(scope, "archive_limits", dict, "scope")

    sources = require_type(result, "sources", list)
    source_ids = set()
    for number, source in enumerate(sources, start=1):
        where = "source " + str(number)
        if not isinstance(source, dict):
            raise ValueError(where + " must be an object")
        for key in ("id", "path", "kind", "sha256", "modified_at"):
            require_type(source, key, str, where)
        require_type(source, "size", int, where)
        require_type(source, "members", list, where)
        if not re.fullmatch(r"EV-[0-9]{4,}", source["id"]):
            raise ValueError(where + " has an invalid id")
        if source["id"] in source_ids:
            raise ValueError("duplicate source id: " + source["id"])
        source_ids.add(source["id"])
        if not re.fullmatch(r"[a-f0-9]{64}", source["sha256"]):
            raise ValueError(where + " has an invalid SHA-256 value")
        validate_timestamp(source["modified_at"], where + " modified_at")
        for member_number, member in enumerate(source["members"], start=1):
            member_where = where + " member " + str(member_number)
            if not isinstance(member, dict):
                raise ValueError(member_where + " must be an object")
            for key in ("reference", "path", "sha256", "modified_at"):
                require_type(member, key, str, member_where)
            require_type(member, "size", int, member_where)
            if not member["reference"].startswith(source["id"] + ":M"):
                raise ValueError(member_where + " has an invalid reference")
            if not re.fullmatch(r"[a-f0-9]{64}", member["sha256"]):
                raise ValueError(member_where + " has an invalid SHA-256 value")
            validate_timestamp(member["modified_at"], member_where + " modified_at")

    if schema_version == "1.1":
        coverage = require_type(result, "coverage", list)
        for number, item in enumerate(coverage, start=1):
            where = "coverage item " + str(number)
            if not isinstance(item, dict):
                raise ValueError(where + " must be an object")
            for key in ("area", "status", "notes"):
                require_type(item, key, str, where)
            require_type(item, "items", int, where)
            if item["status"] not in COVERAGE_STATES:
                raise ValueError(where + " has an unknown status")

        wordpress = require_type(result, "wordpress", dict)
        for key in (
            "detected", "core_present", "wp_admin_present", "wp_includes_present",
            "wp_content_present", "wp_config_present",
        ):
            require_type(wordpress, key, bool, "wordpress")
        for key in ("files_total", "php_files"):
            require_type(wordpress, key, int, "wordpress")
        for key in ("version", "version_source"):
            require_type(wordpress, key, str, "wordpress")
        for key in ("plugins", "themes", "upload_executables"):
            require_type(wordpress, key, list, "wordpress")
        for number, item in enumerate(wordpress["upload_executables"], start=1):
            where = "WordPress upload executable " + str(number)
            if not isinstance(item, dict):
                raise ValueError(where + " must be an object")
            for key in ("path", "sha256", "source_id"):
                require_type(item, key, str, where)
            if not re.fullmatch(r"[a-f0-9]{64}", item["sha256"]):
                raise ValueError(where + " has an invalid SHA-256 value")
            if item["source_id"].split(":", 1)[0] not in source_ids:
                raise ValueError(where + " references an unknown source")

    findings = require_type(result, "findings", list)
    finding_ids = set()
    for number, finding in enumerate(findings, start=1):
        where = "finding " + str(number)
        if not isinstance(finding, dict):
            raise ValueError(where + " must be an object")
        for key in (
            "id", "category", "confidence", "title", "severity", "summary",
            "impact", "recommendation",
        ):
            require_type(finding, key, str, where)
        require_type(finding, "evidence", list, where)
        require_type(finding, "source_ids", list, where)
        if not re.fullmatch(r"IR-[A-F0-9]{10}", finding["id"]):
            raise ValueError(where + " has an invalid id")
        if finding["id"] in finding_ids:
            raise ValueError("duplicate finding id: " + finding["id"])
        finding_ids.add(finding["id"])
        if finding["severity"] not in SEVERITY_ORDER:
            raise ValueError(where + " has an unknown severity")
        if finding["confidence"] not in CONFIDENCE_LEVELS:
            raise ValueError(where + " has an unknown confidence")
        for source_id in finding["source_ids"]:
            if source_id.split(":", 1)[0] not in source_ids:
                raise ValueError(where + " references unknown source " + source_id)

    timeline = require_type(result, "timeline", list)
    timeline_ids = set()
    for number, event in enumerate(timeline, start=1):
        where = "timeline event " + str(number)
        if not isinstance(event, dict):
            raise ValueError(where + " must be an object")
        for key in (
            "id", "timestamp", "timestamp_basis", "category", "source_ip",
            "action", "outcome", "confidence", "summary",
        ):
            require_type(event, key, str, where)
        require_type(event, "evidence_refs", list, where)
        if not re.fullmatch(r"TL-[0-9]{4,}", event["id"]):
            raise ValueError(where + " has an invalid id")
        if event["id"] in timeline_ids:
            raise ValueError("duplicate timeline id: " + event["id"])
        timeline_ids.add(event["id"])
        validate_timestamp(event["timestamp"], where + " timestamp")
        if event["confidence"] not in CONFIDENCE_LEVELS:
            raise ValueError(where + " has an unknown confidence")

    assessment = require_type(result, "assessment", dict)
    for key in ("compromise_status", "initial_access", "database_injection"):
        value = require_type(assessment, key, str, "assessment")
        if value not in ASSESSMENT_STATES:
            raise ValueError("assessment field '" + key + "' has an unknown value")
    require_type(assessment, "summary", str, "assessment")
    require_type(assessment, "limitations", list, "assessment")
    if schema_version == "1.1":
        technical_severity = require_type(
            assessment, "technical_severity", str, "assessment"
        )
        if technical_severity not in SEVERITY_ORDER:
            raise ValueError("assessment technical_severity is unknown")
        incident_state = require_type(
            assessment, "incident_state", str, "assessment"
        )
        if incident_state not in INCIDENT_STATES:
            raise ValueError("assessment incident_state is unknown")
        require_type(assessment, "business_impact", str, "assessment")

        lifecycle = require_type(result, "response_lifecycle", list)
        for number, item in enumerate(lifecycle, start=1):
            where = "response lifecycle item " + str(number)
            if not isinstance(item, dict):
                raise ValueError(where + " must be an object")
            for key in ("phase", "status", "owner", "notes"):
                require_type(item, key, str, where)
        follow_up = require_type(result, "required_follow_up", list)
        if not all(isinstance(item, str) for item in follow_up):
            raise ValueError("required_follow_up must contain strings")
        methodology = require_type(result, "methodology", list)
        for number, item in enumerate(methodology, start=1):
            where = "methodology item " + str(number)
            if not isinstance(item, dict):
                raise ValueError(where + " must be an object")
            for key in ("framework", "application", "reference"):
                require_type(item, key, str, where)

    indicators = require_type(result, "indicators", list)
    for number, indicator in enumerate(indicators, start=1):
        where = "indicator " + str(number)
        if not isinstance(indicator, dict):
            raise ValueError(where + " must be an object")
        for key in ("type", "value", "context", "confidence"):
            require_type(indicator, key, str, where)

    statistics = require_type(result, "statistics", dict)
    for key in (
        "source_files", "archive_members", "duplicate_items", "log_lines",
        "parsed_log_lines", "malformed_log_lines", "sql_lines", "findings_total",
        "timeline_events",
    ):
        require_type(statistics, key, int, "statistics")
    if schema_version == "1.1":
        for key in (
            "auth_log_lines", "parsed_auth_log_lines",
            "malformed_auth_log_lines", "wordpress_files", "php_files",
        ):
            require_type(statistics, key, int, "statistics")
    require_type(result, "errors", list)

    if statistics["source_files"] != len(sources):
        raise ValueError("statistics source_files does not match sources")
    if statistics["findings_total"] != len(findings):
        raise ValueError("statistics findings_total does not match findings")
    if statistics["timeline_events"] != len(timeline):
        raise ValueError("statistics timeline_events does not match timeline")
    return result
