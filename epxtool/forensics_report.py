"""Client-facing Markdown and HTML reports for forensic-analysis artifacts."""

import html

from .findings import SEVERITY_ORDER, count_by_severity, sort_findings
from .forensics_schema import validate_forensics_result
from .report import BRAND, SEVERITY_COLOR, evidence_block, markdown_table_text, markdown_text


def state_label(value):
    """Make a stored assessment state readable."""
    return value.replace("-", " ").title()


def build_forensics_markdown(result):
    """Build a Markdown incident-analysis report."""
    validate_forensics_result(result)
    context = result.get("_report_context", {})
    reviewed_by = context.get("reviewed_by", "")
    client = context.get("client_name") or result["authorization"]["client"]
    report_id = context.get("report_id") or result["case_id"] + "-R1"
    findings = sort_findings(result["findings"])
    assessment = result["assessment"]
    lines = [
        "# Incident Analysis: " + markdown_text(result["site"] or result["case_id"]),
        "",
        "**Prepared by:** " + BRAND + "  ",
    ]
    if client:
        lines.append("**Client:** " + markdown_text(client) + "  ")
    lines.extend([
        "**Report ID:** " + markdown_text(report_id) + "  ",
        "**Case ID:** " + markdown_text(result["case_id"]) + "  ",
        "**Analysis status:** " + markdown_text(result["status"]) + "  ",
        "**Analyst review:** " + (
            "Reviewed by " + markdown_text(reviewed_by)
            if reviewed_by else "Automated draft - review required"
        ) + "  ",
        "**Analysis time:** " + markdown_text(result["started_at"]) + " to " +
        markdown_text(result["finished_at"]) + "  ",
        "**Authorization reference:** " +
        markdown_text(result["authorization"]["reference"] or "Not recorded") + "  ",
    ])
    if context.get("source_sha256"):
        lines.extend([
            "**Source JSON SHA-256:** `" +
            markdown_text(context["source_sha256"]) + "`  ",
            "**Source integrity:** " +
            markdown_text(context.get("integrity_status", "not verified")) + "  ",
        ])
    lines.extend([
        "",
        "**Scope:** Offline static analysis of supplied evidence. Archives were read "
        "without extracting them to disk. Supplied PHP was not executed.",
        "",
        "---",
        "",
        "## Executive assessment",
        "",
        "**" + markdown_text(assessment["summary"]) + "**",
        "",
        "| Question | Assessment |",
        "|----------|------------|",
        "| Server compromise | " +
        markdown_table_text(state_label(assessment["compromise_status"])) + " |",
        "| Initial access method | " +
        markdown_table_text(state_label(assessment["initial_access"])) + " |",
        "| Database injection | " +
        markdown_table_text(state_label(assessment["database_injection"])) + " |",
        "",
        "## Findings at a glance",
        "",
        "| ID | Severity | Confidence | Finding |",
        "|----|----------|------------|---------|",
    ])
    for item in findings:
        lines.append(
            "| " + markdown_table_text(item["id"]) +
            " | " + markdown_table_text(item["severity"]) +
            " | " + markdown_table_text(item["confidence"]) +
            " | " + markdown_table_text(item["title"]) + " |"
        )
    if not findings:
        lines.append("| - | - | - | No findings were generated |")

    lines.extend(["", "## Detailed findings", ""])
    for number, item in enumerate(findings, start=1):
        lines.extend([
            "### " + str(number) + ". " + markdown_text(item["title"]) +
            " - **" + markdown_text(item["severity"]) + "**",
            "",
            "**Finding ID:** `" + markdown_text(item["id"]) + "`  ",
            "**Category:** " + markdown_text(item["category"]) + "  ",
            "**Confidence:** " + markdown_text(item["confidence"]) + "  ",
            "",
            markdown_text(item["summary"]),
            "",
        ])
        if item["impact"]:
            lines.extend([
                "**Why it matters:** " + markdown_text(item["impact"]),
                "",
            ])
        if item["evidence"]:
            lines.extend(["**Evidence:**", ""])
            lines.extend(evidence_block(item["evidence"]))
            lines.append("")
        if item["recommendation"]:
            lines.extend([
                "**Recommended:** " + markdown_text(item["recommendation"]),
                "",
            ])
        lines.extend(["---", ""])

    lines.extend([
        "## Incident timeline",
        "",
        "| Time | Basis | Source | Activity | Outcome | Confidence |",
        "|------|-------|--------|----------|---------|------------|",
    ])
    for event in result["timeline"]:
        lines.append(
            "| " + markdown_table_text(event["timestamp"]) +
            " | " + markdown_table_text(event["timestamp_basis"]) +
            " | " + markdown_table_text(event["source_ip"] or "Server evidence") +
            " | " + markdown_table_text(event["action"]) +
            " | " + markdown_table_text(event["outcome"]) +
            " | " + markdown_table_text(event["confidence"]) + " |"
        )
    if not result["timeline"]:
        lines.append("| - | - | - | No timestamped events | - | - |")

    lines.extend([
        "",
        "## Indicators",
        "",
        "| Type | Value | Context | Confidence |",
        "|------|-------|---------|------------|",
    ])
    for indicator in result["indicators"]:
        lines.append(
            "| " + markdown_table_text(indicator["type"]) +
            " | `" + markdown_table_text(indicator["value"]) +
            "` | " + markdown_table_text(indicator["context"]) +
            " | " + markdown_table_text(indicator["confidence"]) + " |"
        )
    if not result["indicators"]:
        lines.append("| - | - | No indicators generated | - |")

    lines.extend([
        "",
        "## Evidence manifest",
        "",
        "| ID | Supplied path | Type | Size | SHA-256 |",
        "|----|---------------|------|------|----------|",
    ])
    for source in result["sources"]:
        lines.append(
            "| " + markdown_table_text(source["id"]) +
            " | " + markdown_table_text(source["path"]) +
            " | " + markdown_table_text(source["kind"]) +
            " | " + str(source["size"]) +
            " | `" + markdown_table_text(source["sha256"]) + "` |"
        )
    statistics = result["statistics"]
    lines.extend([
        "",
        "Parsed **" + str(statistics["parsed_log_lines"]) + "** of **" +
        str(statistics["log_lines"]) + "** access-log lines and inspected **" +
        str(statistics["sql_lines"]) + "** SQL lines. Duplicate logical evidence "
        "items skipped: **" + str(statistics["duplicate_items"]) + "**.",
        "",
        "## Limitations",
        "",
    ])
    for limitation in assessment["limitations"]:
        lines.append("- " + markdown_text(limitation))
    if result["errors"]:
        lines.extend(["", "## Processing notes", ""])
        for error in result["errors"]:
            lines.append("- " + markdown_text(error))
    if not reviewed_by:
        lines.extend([
            "",
            "**AUTOMATED DRAFT:** A qualified incident-response analyst must validate "
            "the timeline, affected scope, false positives, and remediation before "
            "client delivery.",
        ])
    lines.append("")
    return "\n".join(lines)


def build_forensics_html(result):
    """Build a self-contained HTML incident-analysis report."""
    validate_forensics_result(result)
    context = result.get("_report_context", {})
    reviewed_by = context.get("reviewed_by", "")
    client = context.get("client_name") or result["authorization"]["client"]
    report_id = context.get("report_id") or result["case_id"] + "-R1"
    findings = sort_findings(result["findings"])
    counts = count_by_severity(findings)
    chips = "".join(
        '<span class="chip" style="background:' + SEVERITY_COLOR[severity] + '">' +
        str(counts[severity]) + " " + severity + "</span>"
        for severity in SEVERITY_ORDER if counts[severity]
    )
    finding_rows = "".join(
        "<tr><td>" + html.escape(item["id"]) + "</td><td>" +
        html.escape(item["severity"]) + "</td><td>" +
        html.escape(item["confidence"]) + "</td><td>" +
        html.escape(item["title"]) + "</td></tr>"
        for item in findings
    ) or '<tr><td colspan="4">No findings were generated</td></tr>'
    blocks = ""
    for number, item in enumerate(findings, start=1):
        evidence = ""
        if item["evidence"]:
            evidence = "<pre>" + html.escape("\n".join(item["evidence"])) + "</pre>"
        impact = (
            "<p><b>Why it matters:</b> " + html.escape(item["impact"]) + "</p>"
            if item["impact"] else ""
        )
        recommendation = (
            '<p class="rec"><b>Recommended:</b> ' +
            html.escape(item["recommendation"]) + "</p>"
            if item["recommendation"] else ""
        )
        blocks += (
            '<section class="finding"><h3>' + str(number) + ". " +
            html.escape(item["title"]) + "</h3><p class=\"meta\">" +
            html.escape(item["id"]) + " | " + html.escape(item["severity"]) +
            " | " + html.escape(item["confidence"]) + " | " +
            html.escape(item["category"]) + "</p><p>" +
            html.escape(item["summary"]) + "</p>" + impact + evidence +
            recommendation + "</section>"
        )
    timeline_rows = "".join(
        "<tr><td>" + html.escape(event["timestamp"]) + "</td><td>" +
        html.escape(event["source_ip"] or "Server evidence") + "</td><td>" +
        html.escape(event["action"]) + "</td><td>" +
        html.escape(event["outcome"]) + "</td><td>" +
        html.escape(event["confidence"]) + "</td></tr>"
        for event in result["timeline"]
    ) or '<tr><td colspan="5">No timestamped events</td></tr>'
    indicator_rows = "".join(
        "<tr><td>" + html.escape(item["type"]) + "</td><td><code>" +
        html.escape(item["value"]) + "</code></td><td>" +
        html.escape(item["context"]) + "</td><td>" +
        html.escape(item["confidence"]) + "</td></tr>"
        for item in result["indicators"]
    ) or '<tr><td colspan="4">No indicators generated</td></tr>'
    source_rows = "".join(
        "<tr><td>" + html.escape(item["id"]) + "</td><td>" +
        html.escape(item["path"]) + "</td><td>" + html.escape(item["kind"]) +
        "</td><td>" + str(item["size"]) + "</td><td><code>" +
        html.escape(item["sha256"]) + "</code></td></tr>"
        for item in result["sources"]
    )
    limitations = "".join(
        "<li>" + html.escape(item) + "</li>"
        for item in result["assessment"]["limitations"]
    )
    errors = ""
    if result["errors"]:
        errors = "<h2>Processing notes</h2><ul>" + "".join(
            "<li>" + html.escape(str(item)) + "</li>" for item in result["errors"]
        ) + "</ul>"
    review = (
        '<div class="review reviewed">Reviewed by ' + html.escape(reviewed_by) + "</div>"
        if reviewed_by else
        '<div class="review draft">AUTOMATED DRAFT - ANALYST REVIEW REQUIRED</div>'
    )
    client_text = "<br>Client: " + html.escape(client) if client else ""
    integrity = ""
    if context.get("source_sha256"):
        integrity = (
            "<br>Source SHA-256: <code>" +
            html.escape(context["source_sha256"]) + "</code> (" +
            html.escape(context.get("integrity_status", "not verified")) + ")"
        )
    assessment = result["assessment"]
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>Incident Analysis: " + html.escape(result["site"] or result["case_id"]) +
        "</title><style>"
        "body{font-family:Arial,sans-serif;color:#202124;max-width:980px;margin:auto;"
        "padding:40px 24px;line-height:1.55}h1{margin-bottom:4px}.meta{color:#5f6368;"
        "font-size:13px}.review{margin:14px 0;padding:10px 14px;border-radius:6px;"
        "font-weight:bold}.draft{background:#fff4df;border:1px solid #e6b566}"
        ".reviewed{background:#edf7ed;border:1px solid #81c784}.chip{color:white;"
        "border-radius:999px;padding:3px 10px;margin-right:6px;font-size:12px;"
        "font-weight:bold}.summary{background:#f8f9fa;padding:16px 20px;border-radius:"
        "10px;margin:18px 0}.finding{border:1px solid #ddd;border-radius:10px;"
        "padding:16px 20px;margin:14px 0}table{width:100%;border-collapse:collapse;"
        "margin:14px 0}th,td{text-align:left;border-bottom:1px solid #ddd;padding:8px;"
        "font-size:13px;vertical-align:top}pre{white-space:pre-wrap;background:#f6f8fa;"
        "padding:12px;border-radius:6px;font-size:12px}.rec{background:#f1f8e9;"
        "border-left:3px solid #689f38;padding:9px 12px}code{word-break:break-all}"
        "</style></head><body><h1>Incident Analysis</h1><div class=\"meta\">" +
        html.escape(result["site"] or result["case_id"]) + " | " + BRAND +
        "<br>Report ID: " + html.escape(report_id) + " | Case ID: " +
        html.escape(result["case_id"]) + " | Status: " +
        html.escape(result["status"]) + client_text + integrity + "</div>" +
        review + '<div class="chips">' + chips + "</div>" +
        '<div class="summary"><b>' + html.escape(assessment["summary"]) +
        "</b><br>Compromise: " +
        html.escape(state_label(assessment["compromise_status"])) +
        " | Initial access: " + html.escape(state_label(assessment["initial_access"])) +
        " | Database injection: " +
        html.escape(state_label(assessment["database_injection"])) + "</div>" +
        "<h2>Findings at a glance</h2><table><thead><tr><th>ID</th><th>Severity</th>"
        "<th>Confidence</th><th>Finding</th></tr></thead><tbody>" +
        finding_rows + "</tbody></table><h2>Detailed findings</h2>" + blocks +
        "<h2>Incident timeline</h2><table><thead><tr><th>Time</th><th>Source</th>"
        "<th>Activity</th><th>Outcome</th><th>Confidence</th></tr></thead><tbody>" +
        timeline_rows + "</tbody></table><h2>Indicators</h2><table><thead><tr>"
        "<th>Type</th><th>Value</th><th>Context</th><th>Confidence</th></tr></thead>"
        "<tbody>" + indicator_rows + "</tbody></table><h2>Evidence manifest</h2>"
        "<table><thead><tr><th>ID</th><th>Path</th><th>Type</th><th>Size</th>"
        "<th>SHA-256</th></tr></thead><tbody>" + source_rows +
        "</tbody></table><h2>Limitations</h2><ul>" + limitations + "</ul>" + errors +
        "<footer class=\"meta\">Offline static evidence analysis. Archives were not "
        "extracted to disk and supplied PHP was not executed.</footer></body></html>"
    )
