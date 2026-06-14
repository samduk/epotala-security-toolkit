"""
attack.py
=========

A small, fixed catalog of MITRE ATT&CK techniques that the findings reference.

Each finding can carry an `attack` list. Every entry names ONE adversary
technique the finding maps to or directly enables, so a report reader can place
the weakness in the wider attack picture.

This is a *reference* mapping, not evidence of adversary activity. A missing
header or a public version does not mean anyone has run the technique; it means
the weakness sits on the path that technique would use. We keep the catalog
small and hand-curated on purpose: every mapping below is one a human analyst
can defend, and nothing here is generated automatically from a version string.

The catalog is kept in plain Python so the toolkit stays dependency-free.
"""

# technique id -> (technique name, ATT&CK tactic)
# IDs and names follow the public MITRE ATT&CK matrices (Enterprise + PRE).
TECHNIQUES = {
    "T1592.002": ("Gather Victim Host Information: Software", "Reconnaissance"),
    "T1589": ("Gather Victim Identity Information", "Reconnaissance"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1498.002": ("Network Denial of Service: Reflection Amplification", "Impact"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1040": ("Network Sniffing", "Credential Access"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access"),
    "T1059.007": ("Command and Scripting Interpreter: JavaScript", "Execution"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1539": ("Steal Web Session Cookie", "Credential Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
}

# Public reference page for a technique, e.g. T1110.001 -> .../T1110/001/.
ATTACK_BASE_URL = "https://attack.mitre.org/techniques/"


def technique_url(technique_id):
    """Return the public MITRE ATT&CK URL for a technique id."""
    return ATTACK_BASE_URL + technique_id.replace(".", "/") + "/"


def technique(technique_id):
    """Return one technique reference dictionary for a known technique id."""
    if technique_id not in TECHNIQUES:
        raise KeyError("unknown ATT&CK technique id: " + technique_id)
    name, tactic = TECHNIQUES[technique_id]
    return {
        "id": technique_id,
        "name": name,
        "tactic": tactic,
        "url": technique_url(technique_id),
    }


def techniques(*technique_ids):
    """Return a list of technique references for several technique ids."""
    return [technique(technique_id) for technique_id in technique_ids]
