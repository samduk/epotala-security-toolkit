"""
report.py
=========

Turns a scan result (the dictionary produced by scanner.run_scan) into a
report we can hand to a client.

Two formats:
  * build_markdown(result) -> a Markdown string (good for email / GitHub)
  * build_html(result)     -> a styled HTML page (good for PDF / sending)

We only read the result dictionary here. We never touch the website again, so
a report can always be re-created from a saved .json file.
"""

import html

from .findings import sort_findings, count_by_severity, SEVERITY_ORDER
from .schema import validate_result

BRAND = "Epotala Security"

# A colour for each severity, used in the HTML report.
SEVERITY_COLOR = {
    "Critical": "#b00020",
    "High": "#d93025",
    "Medium": "#e8710a",
    "Low": "#1a73e8",
    "Info": "#5f6368",
}


def markdown_text(value):
    """Escape untrusted text while preserving normal Markdown around it."""
    return html.escape(str(value), quote=False).replace("\n", " ")


def markdown_table_text(value):
    """Escape text used inside a Markdown table cell."""
    return markdown_text(value).replace("|", "\\|")


def evidence_block(lines):
    """Build a code block that cannot be closed by evidence text."""
    text = "\n".join(str(line) for line in lines)
    fence = "```"
    while fence in text:
        fence = fence + "`"
    return [fence, text, fence]


def collect_attack(findings):
    """Return the unique ATT&CK techniques across findings, tactic-ordered.

    Each entry keeps the technique reference plus the finding titles that mapped
    to it, so the coverage section can show why a technique is listed.
    """
    seen = {}
    order = []
    for finding in findings:
        for technique in finding.get("attack", []):
            technique_id = technique["id"]
            if technique_id not in seen:
                seen[technique_id] = {"technique": technique, "findings": []}
                order.append(technique_id)
            title = finding["title"]
            if title not in seen[technique_id]["findings"]:
                seen[technique_id]["findings"].append(title)
    rows = [seen[technique_id] for technique_id in order]
    rows.sort(key=lambda row: (row["technique"]["tactic"], row["technique"]["id"]))
    return rows


def overall_posture(findings, info=None, errors=None, status="complete"):
    """Return one plain-English sentence describing how the site is doing."""
    info = info or {}
    errors = errors or []

    if info.get("reachable") is False:
        return "Inconclusive: the target could not be reached."
    if info.get("is_wordpress") is False:
        return "Inconclusive: WordPress was not detected on the target."

    counts = count_by_severity(findings)
    if status == "failed":
        return "Failed: the assessment could not be completed."
    if status == "incomplete":
        if counts["Critical"] or counts["High"]:
            return ("Incomplete: serious findings were detected, but one or more "
                    "assessment steps did not complete.")
        return "Incomplete: one or more assessment steps did not complete."
    if counts["Critical"] > 0:
        return ("Critical: there are signs of a possible hack or an easily exploited "
                "weakness. Act immediately.")
    if counts["High"] > 0:
        return "At risk: serious misconfigurations were found and should be fixed soon."
    if counts["Medium"] > 0:
        return ("Needs attention: nothing critical, but several settings make the site "
                "easier to attack than it should be.")
    return "Reasonable: no serious issues found in this external review."


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------
def build_markdown(result):
    validate_result(result)
    info = result["info"]
    findings = sort_findings(result["findings"])
    counts = count_by_severity(findings)
    report_context = result.get("_report_context", {})
    reviewed_by = report_context.get("reviewed_by", "")
    client_name = report_context.get(
        "client_name",
        result["authorization"].get("client", ""),
    )
    report_id = report_context.get(
        "report_id",
        result["scan_id"] + "-R1",
    )

    # We build the report line by line and join it together at the end.
    lines = []

    lines.append("# Security Assessment: " + markdown_text(result["target"]))
    lines.append("")
    lines.append("**Prepared by:** " + BRAND + "  ")
    if client_name:
        lines.append("**Client:** " + markdown_text(client_name) + "  ")
    lines.append("**Report ID:** " + markdown_text(report_id) + "  ")
    lines.append("**Scan ID:** " + markdown_text(result["scan_id"]) + "  ")
    lines.append("**Scan status:** " + markdown_text(result["status"]) + "  ")
    if reviewed_by:
        lines.append("**Analyst review:** Reviewed by " +
                     markdown_text(reviewed_by) + "  ")
    else:
        lines.append("**Analyst review:** Automated draft - review required  ")
    lines.append("**Scan time:** " + markdown_text(result["started_at"]) + " to " +
                 markdown_text(result["finished_at"]) + "  ")
    lines.append("**Web server:** " +
                 markdown_text(info.get("server", "unknown")) + "  ")
    if info.get("wp_version"):
        lines.append("**WordPress:** " + markdown_text(info["wp_version"]) + "  ")
    lines.append("**Authorization reference:** " +
                 markdown_text(result["authorization"]["reference"]) + "  ")
    if report_context.get("source_sha256"):
        integrity = report_context.get("integrity_status", "not verified")
        lines.append("**Source JSON SHA-256:** `" +
                     markdown_text(report_context["source_sha256"]) + "`  ")
        lines.append("**Source integrity:** " + markdown_text(integrity) + "  ")
    lines.append("")
    lines.append("**Scope:** External, read-only review. No login, exploitation, "
                 "credential, or modification attempts were made.")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Plain-English summary.
    lines.append("## Summary")
    lines.append("")
    lines.append("**Overall: " +
                 overall_posture(
                     findings,
                     info,
                     result["errors"],
                     result["status"],
                 ) + "**")
    lines.append("")
    finding_word = "finding" if len(findings) == 1 else "findings"
    lines.append("The scan produced **" + str(len(findings)) + " " +
                 finding_word + "**: " + summary_counts_text(counts) + ".")
    lines.append("")

    # Quick table of all findings.
    lines.append("## Findings at a glance")
    lines.append("")
    lines.append("| ID | Severity | Confidence | Finding |")
    lines.append("|----|----------|------------|---------|")
    number = 1
    for finding in findings:
        lines.append("| " + markdown_table_text(finding["id"]) + " | " +
                     markdown_table_text(finding["severity"]) + " | " +
                     markdown_table_text(finding["confidence"]) + " | " +
                     markdown_table_text(finding["title"]) + " |")
        number = number + 1
    if not findings:
        lines.append("| - | - | - | No findings were generated |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Full details for each finding.
    lines.append("## Detailed findings")
    lines.append("")
    number = 1
    for finding in findings:
        lines.append("### " + str(number) + ". " +
                     markdown_text(finding["title"]) + " - **" +
                     markdown_text(finding["severity"]) + "**")
        lines.append("")
        lines.append("**Finding ID:** `" + markdown_text(finding["id"]) + "`  ")
        lines.append("**Category:** " + markdown_text(finding["category"]) + "  ")
        lines.append("**Confidence:** " +
                     markdown_text(finding["confidence"]) + "  ")
        if finding["request_ids"]:
            lines.append("**Supporting requests:** " +
                         ", ".join(
                             "`" + markdown_text(request_id) + "`"
                             for request_id in finding["request_ids"]
                         ))
        lines.append("")
        if finding["summary"]:
            lines.append(markdown_text(finding["summary"]))
            lines.append("")
        if finding["impact"]:
            lines.append("**Why it matters:** " + markdown_text(finding["impact"]))
            lines.append("")
        if finding["evidence"]:
            lines.append("**Evidence:**")
            lines.append("")
            lines.extend(evidence_block(finding["evidence"]))
            lines.append("")
        if finding["recommendation"]:
            lines.append("**Recommended:** " +
                         markdown_text(finding["recommendation"]))
            lines.append("")
        if finding.get("attack"):
            techniques_text = ", ".join(
                markdown_text(
                    technique["id"] + " " + technique["name"] +
                    " (" + technique["tactic"] + ")"
                )
                for technique in finding["attack"]
            )
            lines.append("**MITRE ATT&CK:** " + techniques_text)
            lines.append("")
        lines.append("---")
        lines.append("")
        number = number + 1

    attack_rows = collect_attack(findings)
    if attack_rows:
        lines.append("## MITRE ATT&CK mapping")
        lines.append("")
        lines.append("Reference mapping of findings to adversary techniques. A listed "
                     "technique marks a weakness on that technique's path; it is not "
                     "evidence that the technique was attempted.")
        lines.append("")
        lines.append("| Tactic | Technique | Related findings |")
        lines.append("|--------|-----------|------------------|")
        for row in attack_rows:
            technique = row["technique"]
            lines.append(
                "| " + markdown_table_text(technique["tactic"]) +
                " | " + markdown_table_text(
                    technique["id"] + " " + technique["name"]) +
                " | " + markdown_table_text("; ".join(row["findings"])) + " |"
            )
        lines.append("")

    lines.append("## Assessment coverage")
    lines.append("")
    lines.append("| Check | Status | Findings | Requests |")
    lines.append("|-------|--------|----------|----------|")
    for check in result["checks"]:
        lines.append(
            "| " + markdown_table_text(check["id"]) +
            " | " + markdown_table_text(check["status"]) +
            " | " + str(check["findings_count"]) +
            " | " + str(len(check["request_ids"])) + " |"
        )
    lines.append("")
    statistics = result["statistics"]
    lines.append(
        "Requests: **" + str(statistics.get("network_requests", 0)) +
        "**; bytes received: **" + str(statistics.get("bytes_received", 0)) +
        "**; duration: **" + str(statistics.get("duration_seconds", 0)) +
        " seconds**."
    )
    lines.append("")

    # If any checks crashed, note it honestly at the bottom.
    if result["errors"]:
        lines.append("## Scan notes")
        lines.append("")
        for error in result["errors"]:
            lines.append("- " + markdown_text(error))
        lines.append("")

    if not reviewed_by:
        lines.append("**AUTOMATED DRAFT:** A qualified analyst must verify severity, "
                     "business impact, false positives, and remediation before client "
                     "delivery.")
        lines.append("")
    lines.append("*This was a read-only external check. Confirming a suspected hack and "
                 "full malware cleanup need server access under a Recovery engagement.*")
    lines.append("")

    return "\n".join(lines)


def summary_counts_text(counts):
    """Make text like '1 critical, 2 high, 3 medium' (skipping zero counts)."""
    parts = []
    for severity in SEVERITY_ORDER:
        if counts[severity] > 0:
            parts.append(str(counts[severity]) + " " + severity.lower())
    if not parts:
        return "no findings"
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
def build_html(result):
    validate_result(result)
    info = result["info"]
    findings = sort_findings(result["findings"])
    counts = count_by_severity(findings)
    report_context = result.get("_report_context", {})
    reviewed_by = report_context.get("reviewed_by", "")
    client_name = report_context.get(
        "client_name",
        result["authorization"].get("client", ""),
    )
    report_id = report_context.get(
        "report_id",
        result["scan_id"] + "-R1",
    )

    # Coloured chips showing how many of each severity.
    severity_chips = ""
    for severity in SEVERITY_ORDER:
        if counts[severity] > 0:
            severity_chips = severity_chips + (
                '<span class="chip" style="background:' +
                SEVERITY_COLOR[severity] + '">' +
                str(counts[severity]) + " " + severity + "</span>"
            )

    # The rows of the summary table.
    rows = ""
    number = 1
    for finding in findings:
        color = SEVERITY_COLOR.get(finding["severity"], "#5f6368")
        rows = rows + ("<tr><td>" + html.escape(finding["id"]) + "</td>"
                       '<td><span class="sev" style="background:' + color + '">' +
                       finding["severity"] + "</span></td>"
                       "<td>" + html.escape(finding["confidence"]) + "</td>"
                       "<td>" + html.escape(finding["title"]) + "</td></tr>")
        number = number + 1
    if not rows:
        rows = '<tr><td colspan="4">No findings were generated</td></tr>'

    # One detailed block per finding.
    blocks = ""
    number = 1
    for finding in findings:
        color = SEVERITY_COLOR.get(finding["severity"], "#5f6368")

        evidence_html = ""
        if finding["evidence"]:
            joined = "\n".join(finding["evidence"])
            evidence_html = "<pre>" + html.escape(joined) + "</pre>"

        impact_html = ""
        if finding["impact"]:
            impact_html = "<p><b>Why it matters:</b> " + html.escape(finding["impact"]) + "</p>"

        rec_html = ""
        if finding["recommendation"]:
            rec_html = ('<p class="rec"><b>Recommended:</b> ' +
                        html.escape(finding["recommendation"]) + "</p>")

        attack_html = ""
        if finding.get("attack"):
            attack_links = " ".join(
                '<a class="attack" href="' + html.escape(technique["url"]) +
                '">' + html.escape(technique["id"]) + " " +
                html.escape(technique["name"]) + "</a>"
                for technique in finding["attack"]
            )
            attack_html = ('<p class="finding-meta"><b>MITRE ATT&amp;CK:</b> ' +
                           attack_links + "</p>")

        request_html = ""
        if finding["request_ids"]:
            request_html = (
                '<p class="finding-meta"><b>Supporting requests:</b> ' +
                html.escape(", ".join(finding["request_ids"])) + "</p>"
            )

        blocks = blocks + (
            '<div class="finding">'
            "<h3>" + str(number) + ". " + html.escape(finding["title"]) +
            ' <span class="sev" style="background:' + color + '">' +
            finding["severity"] + "</span></h3>"
            '<p class="finding-meta"><b>ID:</b> ' + html.escape(finding["id"]) +
            " &middot; <b>Category:</b> " + html.escape(finding["category"]) +
            " &middot; <b>Confidence:</b> " +
            html.escape(finding["confidence"]) + "</p>" +
            request_html +
            "<p>" + html.escape(finding["summary"]) + "</p>" +
            impact_html + evidence_html + rec_html + attack_html +
            "</div>"
        )
        number = number + 1

    notes_html = ""
    if result["errors"]:
        note_items = ""
        for error in result["errors"]:
            note_items = note_items + "<li>" + html.escape(str(error)) + "</li>"
        notes_html = "<h2>Scan notes</h2><ul>" + note_items + "</ul>"

    wp_text = ""
    if info.get("wp_version"):
        wp_text = " &middot; WordPress " + html.escape(info["wp_version"])

    attack_section = ""
    attack_rows = collect_attack(findings)
    if attack_rows:
        attack_table_rows = ""
        for row in attack_rows:
            technique = row["technique"]
            attack_table_rows += (
                "<tr>\n"
                "<td>" + html.escape(technique["tactic"]) + "</td>\n"
                '<td><a href="' + html.escape(technique["url"]) + '">' +
                html.escape(technique["id"]) + " " +
                html.escape(technique["name"]) + "</a></td>\n"
                "<td>" + html.escape("; ".join(row["findings"])) + "</td>\n"
                "</tr>\n"
            )
        attack_section = (
            "<h2>MITRE ATT&amp;CK mapping</h2>"
            '<p class="meta">Reference mapping of findings to adversary techniques. '
            "A listed technique marks a weakness on that technique's path; it is not "
            "evidence that the technique was attempted.</p>"
            "<table><thead><tr><th>Tactic</th><th>Technique</th>"
            "<th>Related findings</th></tr></thead><tbody>" +
            attack_table_rows + "</tbody></table>"
        )

    coverage_rows = ""
    for check in result["checks"]:
        coverage_rows += (
            "<tr><td>" + html.escape(check["id"]) + "</td>"
            "<td>" + html.escape(check["status"]) + "</td>"
            "<td>" + str(check["findings_count"]) + "</td>"
            "<td>" + str(len(check["request_ids"])) + "</td></tr>"
        )

    review_html = (
        '<div class="review reviewed">Reviewed by ' + html.escape(reviewed_by) +
        "</div>"
        if reviewed_by else
        '<div class="review draft">AUTOMATED DRAFT - ANALYST REVIEW REQUIRED</div>'
    )

    client_html = ""
    if client_name:
        client_html = "<br>Client: " + html.escape(client_name)

    integrity_html = ""
    if report_context.get("source_sha256"):
        integrity_html = (
            "<br>Source SHA-256: <code>" +
            html.escape(report_context["source_sha256"]) +
            "</code> (" +
            html.escape(report_context.get("integrity_status", "not verified")) +
            ")"
        )

    # Put the whole page together. The CSS just makes it look tidy.
    page = (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>Security Assessment: " + html.escape(result["target"]) + "</title>\n"
        "<style>\n"
        "body { font-family: Arial, Helvetica, sans-serif; color:#202124;"
        " max-width:840px; margin:0 auto; padding:40px 24px; line-height:1.6; }\n"
        "h1 { font-size:26px; margin-bottom:4px; }\n"
        "h3 { margin:0 0 8px; font-size:17px; }\n"
        ".meta { color:#5f6368; font-size:13px; }\n"
        ".finding-meta { color:#5f6368; font-size:12px; }\n"
        ".review { margin:14px 0; padding:10px 14px; border-radius:6px;"
        " font-weight:bold; font-size:13px; }\n"
        ".review.draft { color:#7a4100; background:#fff4df; border:1px solid #e6b566; }\n"
        ".review.reviewed { color:#1b5e20; background:#edf7ed; border:1px solid #81c784; }\n"
        ".chip, .sev { color:#fff; border-radius:999px; padding:2px 10px;"
        " font-size:12px; font-weight:bold; margin-right:6px; display:inline-block; }\n"
        ".sev { font-size:11px; }\n"
        "table { width:100%; border-collapse:collapse; margin:16px 0; }\n"
        "th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #e0e0e0;"
        " font-size:14px; vertical-align:top; }\n"
        ".finding { border:1px solid #e0e0e0; border-radius:10px; padding:16px 20px;"
        " margin:14px 0; }\n"
        "pre { background:#f6f8fa; border-radius:6px; padding:10px 12px; overflow:auto;"
        " font-size:12px; }\n"
        ".rec { background:#f1f8e9; border-left:3px solid #689f38; padding:8px 12px; }\n"
        ".attack { display:inline-block; margin:2px 6px 2px 0; padding:2px 8px;"
        " background:#ede7f6; color:#4527a0; border-radius:4px; font-size:11px;"
        " text-decoration:none; }\n"
        ".summary { background:#f8f9fa; border-radius:10px; padding:16px 20px; }\n"
        "footer { color:#5f6368; font-size:12px; margin-top:32px;"
        " border-top:1px solid #e0e0e0; padding-top:16px; }\n"
        "</style></head><body>\n"
        "<h1>Security Assessment</h1>\n"
        '<div class="meta">' + html.escape(result["target"]) + " &middot; " + BRAND +
        " &middot; " + html.escape(result["started_at"]) +
        client_html +
        "<br>Report ID: " + html.escape(report_id) +
        " &middot; Scan ID: " + html.escape(result["scan_id"]) +
        " &middot; Status: " + html.escape(result["status"]) +
        "<br>Authorization: " +
        html.escape(result["authorization"]["reference"]) +
        "<br>Server: " + html.escape(info.get("server", "unknown")) +
        wp_text + integrity_html + "</div>\n" +
        review_html +
        '<div class="chips">' + severity_chips + "</div>\n"
        '<div class="summary"><b>Overall:</b> ' +
        html.escape(overall_posture(
            findings,
            info,
            result["errors"],
            result["status"],
        )) + "</div>\n"
        "<h2>Findings at a glance</h2>\n"
        "<table><thead><tr><th>ID</th><th>Severity</th><th>Confidence</th>"
        "<th>Finding</th></tr></thead>"
        "<tbody>" + rows + "</tbody></table>\n"
        "<h2>Detailed findings</h2>\n" + blocks +
        attack_section +
        "<h2>Assessment coverage</h2>"
        "<table><thead><tr><th>Check</th><th>Status</th><th>Findings</th>"
        "<th>Requests</th></tr></thead><tbody>" + coverage_rows +
        "</tbody></table>"
        "<p class=\"meta\">Network requests: " +
        str(result["statistics"].get("network_requests", 0)) +
        " &middot; Bytes received: " +
        str(result["statistics"].get("bytes_received", 0)) +
        " &middot; Duration: " +
        str(result["statistics"].get("duration_seconds", 0)) +
        " seconds</p>" +
        notes_html +
        "<footer>Read-only external assessment. No login, exploitation, credential, or "
        "modification attempts were made. Confirming a suspected hack needs server access "
        "under a Recovery engagement. Scope: " + html.escape(result["target"]) +
        ".</footer>\n"
        "</body></html>"
    )
    return page
