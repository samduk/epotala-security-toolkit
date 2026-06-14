"""
cve.py
======

Optional, opt-in CVE correlation for the components we detected.

This is the ONE part of the toolkit that talks to a third party. It is off by
default. When enabled with `--cve-source`, it sends the detected component slugs
and reported versions to a vulnerability feed (WPScan) and turns matching
advisories into findings.

Honesty rules that keep this credible:

  * The reported version is itself unverified (read from a public readme or
    stylesheet that can be stale or spoofed). So every CVE match is a CANDIDATE,
    capped at "Medium" confidence, never "Confirmed".
  * A match means "the reported version is at or below the version that fixed a
    published advisory" - not that the component is active or reachable.
  * Sending component names to a feed moves client inventory outside the
    engagement boundary. The caller must pass explicit authorization; the CLI
    warns before any request leaves.

Network access uses only the Python standard library, so the toolkit keeps its
dependency-free installation.
"""

import json
import ssl
import urllib.error
import urllib.request

from . import __version__
from .attack import techniques
from .findings import make_finding

WPSCAN_BASE_URL = "https://wpscan.com/api/v3"
USER_AGENT = "epxtool/" + __version__ + " (authorized security assessment)"

# Sources we know how to query. Kept as a set so the CLI can validate input.
SUPPORTED_SOURCES = ("wpscan",)


def parse_version(text):
    """Return a comparable tuple of integers for a dotted version string.

    "10.6.2" -> (10, 6, 2). Non-numeric trailing parts are ignored. Returns an
    empty tuple when nothing numeric can be read, which callers treat as
    "version unknown".
    """
    parts = []
    for chunk in str(text).strip().split("."):
        number = ""
        for character in chunk:
            if character.isdigit():
                number += character
            else:
                break
        if number == "":
            break
        parts.append(int(number))
    return tuple(parts)


def version_is_affected(reported, fixed_in):
    """Decide whether a reported version is affected by an advisory.

    Returns one of: "affected", "fixed", or "unknown". "unknown" is returned
    when we cannot compare (missing reported version), so the caller can present
    the advisory for manual review instead of asserting exploitability.
    """
    reported_tuple = parse_version(reported)
    if not reported_tuple:
        return "unknown"
    if not fixed_in:
        # No fix published yet: a known-good version cannot be asserted.
        return "affected"
    fixed_tuple = parse_version(fixed_in)
    if not fixed_tuple:
        return "unknown"
    return "affected" if reported_tuple < fixed_tuple else "fixed"


def default_fetcher(path, api_key, timeout=10, verify_tls=True):
    """Fetch one WPScan API path. Returns (status, parsed_json_or_None, error)."""
    url = WPSCAN_BASE_URL + path
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Authorization": "Token token=" + api_key,
    }
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
            return response.status, json.loads(body), ""
    except urllib.error.HTTPError as error:
        # 404 means "no advisories on record for this slug" - not an error.
        if error.code == 404:
            return 404, {}, ""
        return error.code, None, "HTTP " + str(error.code) + " from vulnerability feed"
    except (urllib.error.URLError, ValueError, OSError) as error:
        return 0, None, "vulnerability feed request failed: " + str(error)


def advisories_from_payload(payload, slug):
    """Pull the vulnerability list for one slug out of a WPScan payload."""
    if not isinstance(payload, dict):
        return []
    entry = payload.get(slug)
    if not isinstance(entry, dict):
        return []
    vulnerabilities = entry.get("vulnerabilities", [])
    return vulnerabilities if isinstance(vulnerabilities, list) else []


def cve_label(vulnerability):
    """Return a human CVE label for one advisory, e.g. 'CVE-2024-1234'."""
    references = vulnerability.get("references", {})
    if isinstance(references, dict):
        cves = references.get("cve", [])
        if isinstance(cves, list) and cves:
            return "CVE-" + str(cves[0])
    return vulnerability.get("title", "advisory")


def endpoint_for(kind, slug, wp_version):
    """Return the WPScan API path for a component kind."""
    if kind == "core":
        return "/wordpresses/" + wp_version.replace(".", "")
    if kind == "theme":
        return "/themes/" + slug
    return "/plugins/" + slug


def severity_from_cvss(score):
    """Map a CVSS base score to a report severity band."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "Medium"
    if value >= 9.0:
        return "Critical"
    if value >= 7.0:
        return "High"
    if value >= 4.0:
        return "Medium"
    if value > 0:
        return "Low"
    return "Medium"


def cvss_score(vulnerability):
    """Best-effort read of a CVSS base score from a WPScan advisory."""
    cvss = vulnerability.get("cvss")
    if isinstance(cvss, dict):
        return cvss.get("score")
    return None


def build_component_finding(slug, kind, reported_version, matches):
    """Build one finding summarizing the candidate CVEs for a component."""
    severities = [severity_from_cvss(cvss_score(match["vuln"])) for match in matches]
    order = ["Critical", "High", "Medium", "Low", "Info"]
    severity = min(severities, key=order.index) if severities else "Medium"

    any_unknown = any(match["state"] == "unknown" for match in matches)
    confidence = "Low" if any_unknown else "Medium"

    version_text = reported_version if parse_version(reported_version) else "unknown"
    evidence = []
    for match in matches:
        vuln = match["vuln"]
        fixed = vuln.get("fixed_in") or "no fix published"
        note = "" if match["state"] == "affected" else " [reported version unknown - verify]"
        evidence.append(
            cve_label(vuln) + " - " + str(vuln.get("title", "")).strip() +
            " (fixed in " + str(fixed) + ")" + note
        )

    count = len(matches)
    cve_word = "advisory" if count == 1 else "advisories"
    return make_finding(
        title="Known vulnerabilities reported for " + kind + " " + slug +
              " " + version_text,
        severity=severity,
        summary="A vulnerability feed lists " + str(count) + " published " +
                cve_word + " whose fixed version is newer than the version "
                "reported for this component.",
        impact="If the reported version is accurate and the component is active, "
               "these advisories may be exploitable. The reported version is not "
               "verified by this external scan, so each match needs analyst "
               "confirmation against the deployed code.",
        recommendation="Confirm the deployed version and whether the component is "
                       "active, then update it and validate each advisory against a "
                       "current vulnerability source before reporting it as exploitable.",
        evidence=evidence,
        category="Vulnerable Component",
        confidence=confidence,
        attack=techniques("T1190"),
    )


def correlate(wp_version, components, api_key, source="wpscan",
              timeout=10, verify_tls=True, fetcher=None):
    """Correlate detected components against a vulnerability feed.

    Returns (findings, errors). Network failures become errors, never crashes,
    so an unreachable feed leaves the rest of the scan intact.
    """
    if source not in SUPPORTED_SOURCES:
        return [], ["unsupported CVE source: " + str(source)]
    if not api_key:
        return [], ["CVE correlation skipped: no API key was provided"]

    fetch = fetcher or default_fetcher
    findings = []
    errors = []

    targets = []
    if wp_version:
        targets.append(("core", "wordpress", wp_version))
    for slug in sorted(components):
        details = components[slug]
        targets.append((details["kind"], slug, details.get("version", "")))

    for kind, slug, reported_version in targets:
        path = endpoint_for(kind, slug, reported_version if kind == "core" else "")
        if kind == "core" and not parse_version(reported_version):
            continue
        status, payload, error = fetch(path, api_key, timeout, verify_tls)
        if error:
            errors.append(slug + ": " + error)
            continue
        if status == 404 or payload is None:
            continue

        lookup_slug = "wordpress" if kind == "core" else slug
        advisories = advisories_from_payload(payload, lookup_slug)
        matches = []
        for vuln in advisories:
            if not isinstance(vuln, dict):
                continue
            state = version_is_affected(reported_version, vuln.get("fixed_in"))
            if state in ("affected", "unknown"):
                matches.append({"vuln": vuln, "state": state})
        if matches:
            findings.append(
                build_component_finding(slug, kind, reported_version, matches)
            )

    return findings, errors
