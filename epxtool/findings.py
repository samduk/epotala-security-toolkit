"""
findings.py
===========

A "finding" is one problem we discovered on the website.

To keep things simple, a finding is just a plain dictionary with these keys:

    title           - short headline, e.g. "Directory listing enabled"
    severity        - how serious: "Critical", "High", "Medium", "Low", or "Info"
    category        - broad control area, e.g. "Security Misconfiguration"
    confidence      - evidence confidence: "Confirmed", "High", "Medium", or "Low"
    summary         - one or two sentences explaining what we found
    impact          - why it matters to the site owner
    recommendation  - what to do about it
    evidence        - a list of short text lines that prove the finding
    attack          - a list of MITRE ATT&CK technique references (may be empty)

This file gives us:
  * make_finding(...)  - builds one of those dictionaries (so every finding
                         has the same shape and we never forget a key)
  * SEVERITY_ORDER     - the order we want to show severities in (worst first)
  * sort_findings(...) - sorts a list of findings worst-first
"""

# Worst first. We use this list both for sorting and for counting.
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
CONFIDENCE_LEVELS = ["Confirmed", "High", "Medium", "Low"]


def make_finding(title, severity, summary,
                 impact="", recommendation="", evidence=None,
                 category="General", confidence="Medium", request_ids=None,
                 attack=None):
    """Build one finding dictionary. `evidence` defaults to an empty list."""
    if evidence is None:
        evidence = []
    if request_ids is None:
        request_ids = []
    if attack is None:
        attack = []
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "confidence": confidence,
        "summary": summary,
        "impact": impact,
        "recommendation": recommendation,
        "evidence": evidence,
        "request_ids": request_ids,
        "attack": attack,
    }


def severity_rank(finding):
    """Return a number for a finding's severity so we can sort.

    Lower number = more serious (Critical is 0, Info is 4). We use the position
    in SEVERITY_ORDER. Unknown severities go to the bottom.
    """
    severity = finding["severity"]
    if severity in SEVERITY_ORDER:
        return SEVERITY_ORDER.index(severity)
    return len(SEVERITY_ORDER)


def sort_findings(findings):
    """Return the findings sorted worst-first (Critical, High, Medium, ...)."""
    return sorted(findings, key=severity_rank)


def count_by_severity(findings):
    """Return a dictionary like {"Critical": 1, "High": 2, ...}."""
    counts = {}
    for severity in SEVERITY_ORDER:
        counts[severity] = 0
    for finding in findings:
        severity = finding["severity"]
        if severity in counts:
            counts[severity] = counts[severity] + 1
    return counts
