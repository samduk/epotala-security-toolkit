"""
checks.py
=========

This is the heart of the toolkit. Each "check" looks for ONE kind of problem.

Every check is a normal function that:
  * takes the site address (`base_url`), the facts we gathered (`info`),
    and the bounded HTTP client (`client`)
  * returns a LIST of findings (it may find zero, one, or several)

At the very bottom there is a list called ALL_CHECKS. To add a new check you
write a function and add it to that list. Nothing else is needed.

IMPORTANT: every check is "read only". We only look at pages; we never log in,
never send attacks, and never change anything on the site.
"""

import html as html_module
import re
from urllib.parse import unquote, urlsplit

from .http_helper import site_url
from .findings import make_finding
from .attack import techniques


def info_request_ids(info, key):
    """Return discovery request ids without assuming optional data exists."""
    evidence = info.get("evidence_requests", {})
    return list(evidence.get(key, []))


# ---------------------------------------------------------------------------
# Check 1: Does the server tell everyone its exact version?
# ---------------------------------------------------------------------------
def check_server_banner(_base_url, info, _client):
    findings = []
    server = info.get("server", "unknown")
    if server and server != "unknown" and re.search(r"\d+(?:\.\d+)+", server):
        findings.append(make_finding(
            title="Server banner reveals software version",
            severity="Info",
            summary="The web server announces its name and version: " + server,
            impact="Knowing the exact version helps an attacker look up matching exploits.",
            recommendation="Hide the version (for Apache, set 'ServerTokens Prod').",
            evidence=["Server: " + server],
            category="Information Disclosure",
            confidence="High",
            request_ids=info_request_ids(info, "home"),
            attack=techniques("T1592.002"),
        ))
    return findings


# ---------------------------------------------------------------------------
# Check 2: Is the WordPress version visible?
# ---------------------------------------------------------------------------
def check_wp_version(_base_url, info, _client):
    findings = []
    version = info.get("wp_version", "")
    if version:
        findings.append(make_finding(
            title="WordPress version is public (" + version + ")",
            severity="Info",
            summary="The WordPress version (" + version + ") can be read by anyone.",
            impact="The version helps with inventory, but being outdated is the real risk.",
            recommendation="Confirm the version on the server and keep WordPress updated. "
                           "Do not rely on hiding the version as a security control.",
            evidence=["WordPress " + version],
            category="Asset Inventory",
            confidence="Medium",
            request_ids=info_request_ids(info, "wp_version"),
            attack=techniques("T1592.002"),
        ))
    return findings


# ---------------------------------------------------------------------------
# Check 3: List public plugin/theme references for manual review.
# ---------------------------------------------------------------------------
def check_components(_base_url, info, _client):
    findings = []
    components = info.get("components", {})
    if components:
        # Build one evidence line per component, e.g. "plugin woocommerce 10.6.2".
        evidence = []
        for slug in sorted(components):
            details = components[slug]
            evidence.append(details["kind"] + " " + slug + " " + details["version"])

        reference_word = "reference" if len(components) == 1 else "references"
        findings.append(make_finding(
            title=str(len(components)) + " public plugin/theme " +
                  reference_word + " found",
            severity="Info",
            summary="Public pages referenced these plugins or themes. Reported versions "
                    "come from public readme or stylesheet files.",
            impact="Public detection cannot prove whether every component is active or "
                   "whether the reported file matches the deployed code.",
            recommendation="Confirm active components and exact versions with server or "
                           "WordPress admin access, then check them against a current "
                           "vulnerability source.",
            evidence=evidence,
            category="Asset Inventory",
            confidence="Medium",
            request_ids=info_request_ids(info, "components"),
            attack=techniques("T1592.002"),
        ))
    return findings


# ---------------------------------------------------------------------------
# Check 4: Can anyone read the list of usernames?
# ---------------------------------------------------------------------------
def check_user_enumeration(base_url, info, client):
    findings = []
    if not info.get("is_wordpress"):
        return findings

    users = info.get("users", [])

    # A second source is /?author=1 redirecting to a public author archive.
    author = client.fetch(site_url(base_url, "?author=1"))
    author_path = urlsplit(author["final_url"]).path
    author_leaks = author["status"] == 200 and "/author/" in author_path

    if users or author_leaks:
        evidence = list(users)
        if author_leaks:
            evidence.append("/?author=1 redirects to " + author["final_url"])

        findings.append(make_finding(
            title="Public author names and slugs can be enumerated",
            severity="Low",
            summary="Author names or public slugs are visible through the REST API and/or "
                    "author archive redirects.",
            impact="A public author slug may resemble a login name, but this external check "
                   "cannot prove that they are the same.",
            recommendation="Use a public display name and author slug that differ from the "
                           "login name. Restrict author enumeration only if the site does "
                           "not need public author archives or API user data.",
            evidence=evidence,
            category="Information Disclosure",
            confidence="Medium",
            request_ids=(
                info_request_ids(info, "users") + [author["request_id"]]
            ),
            attack=techniques("T1589", "T1110.001"),
        ))
    return findings


# ---------------------------------------------------------------------------
# Check 5: Is XML-RPC turned on with the risky methods?
# ---------------------------------------------------------------------------
def check_xmlrpc(base_url, info, client):
    findings = []
    if not info.get("is_wordpress"):
        return findings

    # We POST a small request asking the server which methods it supports.
    request_body = (
        '<?xml version="1.0"?><methodCall>'
        '<methodName>system.listMethods</methodName></methodCall>'
    ).encode("utf-8")

    response = client.fetch(
        site_url(base_url, "xmlrpc.php"),
        method="POST",
        data=request_body,
        content_type="text/xml",
    )

    # Match exact method names. A normal error page mentioning "pingback"
    # should not become a finding.
    methods = set(re.findall(r"<string>\s*([^<]+?)\s*</string>", response["body"]))
    has_pingback = response["status"] == 200 and "pingback.ping" in methods
    has_multicall = response["status"] == 200 and "system.multicall" in methods

    if has_pingback or has_multicall:
        risky = []
        attack_ids = []
        if has_pingback:
            risky.append("pingback.ping")
            attack_ids.append("T1498.002")  # pingback enables reflection abuse
        if has_multicall:
            risky.append("system.multicall")
            attack_ids.append("T1110.001")  # multicall amplifies password guessing
        findings.append(make_finding(
            title="XML-RPC is enabled with risky methods",
            severity="Medium",
            summary="The file xmlrpc.php offers methods that attackers abuse.",
            impact="'multicall' lets attackers try many passwords in one request; "
                   "'pingback' can be used to attack other websites through yours.",
            recommendation="Turn off XML-RPC if you do not use it, or at least block the "
                           "pingback and multicall methods.",
            evidence=risky,
            category="Attack Surface",
            confidence="High",
            request_ids=[response["request_id"]],
            attack=techniques(*attack_ids),
        ))
    return findings


# ---------------------------------------------------------------------------
# Check 6: Are sensitive files (backups, config, .env) downloadable?
# ---------------------------------------------------------------------------
def check_exposed_files(base_url, _info, client):
    findings = []
    risky_paths = [
        ".env",
        "wp-config.php.bak",
        "wp-config.php~",
        "wp-config.php.save",
        "wp-content/debug.log",
        ".git/config",
        "backup.zip",
        "backup.sql",
    ]

    found = []
    request_ids = []
    for path in risky_paths:
        response = client.fetch(site_url(base_url, path))
        request_ids.append(response["request_id"])
        if response["status"] == 200 and looks_like_sensitive_file(path, response["body"]):
            size_text = str(response["byte_length"]) + " bytes read"
            if response["truncated"]:
                size_text = size_text + ", response truncated"
            found.append("/" + path + " (" + size_text + ")")

    if found:
        findings.append(make_finding(
            title="Sensitive file(s) can be downloaded",
            severity="High",
            summary="Backup, config, or version-control files are reachable over the web.",
            impact="These files can leak database passwords, secret keys, or source code.",
            recommendation="Delete these files from the public folder and block access to "
                           "backups, dotfiles, and .git directories.",
            evidence=found,
            category="Sensitive Data Exposure",
            confidence="High",
            request_ids=request_ids,
            attack=techniques("T1552.001"),
        ))
    return findings


def looks_like_sensitive_file(path, body):
    """Check for content expected inside each sensitive file type.

    Many websites return their normal homepage with status 200 for every missing
    address. Content checks prevent those "soft 404" pages becoming findings.
    """
    if path == ".env":
        assignments = re.findall(
            r"^[A-Z_][A-Z0-9_]*\s*=\s*.+$",
            body,
            re.MULTILINE,
        )
        return len(assignments) >= 2

    if path.startswith("wp-config.php"):
        return "define(" in body and (
            "DB_NAME" in body or "AUTH_KEY" in body or "DB_PASSWORD" in body
        )

    if path == "wp-content/debug.log":
        return bool(re.search(
            r"PHP (?:Fatal error|Warning|Notice|Deprecated)|Stack trace:",
            body,
            re.IGNORECASE,
        ))

    if path == ".git/config":
        return "[core]" in body and "repositoryformatversion" in body

    if path.endswith(".zip"):
        return body.startswith("PK")

    if path.endswith(".sql"):
        return bool(re.search(
            r"(?:-- (?:MySQL|MariaDB) dump|CREATE TABLE|INSERT INTO)",
            body,
            re.IGNORECASE,
        ))

    return False


# ---------------------------------------------------------------------------
# Check 7: Directory listing + suspicious files in the uploads folder.
# ---------------------------------------------------------------------------

# Two different ideas of "dangerous", because context matters:
#
# 1) EXECUTABLE_EXT - a runnable file type (.php, .exe, ...). This is normal in
#    WordPress core folders (wp-includes is FULL of .php), so we only treat it as
#    dangerous when we find it inside the UPLOADS folder, which should only ever
#    hold images and documents.
#
# 2) SUSPICIOUS_NAME - a name that deserves inspection (shell, c99, xss, ...).
#    We only apply this name check inside uploads to avoid false positives in
#    normal WordPress or plugin source files.
EXECUTABLE_EXT = re.compile(
    r"\.(php\d?|phtml|phar|asp|aspx|jsp|exe|sh)$",
    re.IGNORECASE,
)
SUSPICIOUS_NAME = re.compile(
    r"xss|shell|c99|r57|wso|webshell|backdoor|filesman",
    re.IGNORECASE,
)


def check_directory_listing(base_url, _info, client):
    findings = []

    listed_folders = []     # folders the server let us browse
    suspicious_files = []   # suspicious names that still need manual inspection
    executable_files = []   # server-executable extensions inside uploads
    active_svg_files = []   # SVG text containing active script indicators
    log_folders = []        # folders likely holding logs/backups
    listing_request_ids = []
    suspicious_request_ids = []

    # We start at a few common folders and follow any sub-folders we can browse.
    folders_to_visit = ["wp-content/uploads/", "wp-content/", "wp-includes/"]
    already_visited = []

    while folders_to_visit and len(already_visited) < 40:
        folder = folders_to_visit.pop(0)
        if folder in already_visited:
            continue
        already_visited.append(folder)

        response = client.fetch(site_url(base_url, folder))
        listing_request_ids.append(response["request_id"])

        if response["status"] != 200 or not is_directory_listing(response["body"]):
            continue

        listed_folders.append("/" + folder)

        # Are we inside the uploads folder? (where .php files do not belong)
        inside_uploads = folder.startswith("wp-content/uploads")

        # Pull out the file/folder names linked on the listing page.
        for name in find_listing_entries(response["body"]):
            full_path = "/" + folder + name

            # Never request server-executable files: opening a web shell could
            # trigger it. The extension inside uploads is enough to escalate.
            if inside_uploads and EXECUTABLE_EXT.search(name):
                executable_files.append(full_path)

            # Static SVG text is safe to download as data. Inspect it for
            # concrete script indicators instead of relying only on its name.
            elif inside_uploads and SUSPICIOUS_NAME.search(name):
                indicators = []
                if name.lower().endswith(".svg"):
                    file_response = client.fetch(site_url(base_url, folder + name))
                    suspicious_request_ids.append(file_response["request_id"])
                    if file_response["status"] == 200:
                        indicators = find_svg_script_indicators(file_response["body"])

                if indicators:
                    active_svg_files.append(
                        full_path + " (" + ", ".join(indicators) + ")"
                    )
                else:
                    suspicious_files.append(full_path)

            # If it is a sub-folder, note logs/backups, and explore it ONLY when
            # it is under uploads (that is where hidden attacker files live, and
            # it keeps us out of the huge, normal wp-includes tree).
            if name.endswith("/"):
                lower = name.lower()
                if "log" in lower or "backup" in lower or "private" in lower:
                    log_folders.append(full_path)
                if inside_uploads and len(already_visited) < 40:
                    folders_to_visit.append(folder + name)

    # --- Now turn what we saw into findings. ---

    if listed_folders:
        findings.append(make_finding(
            title="Directory listing is enabled",
            severity="Medium",
            summary="The web server shows browsable file listings for site folders.",
            impact="Visitors can inventory filenames and folders. The impact becomes more "
                   "serious if a listed file itself contains private information.",
            recommendation="Turn off directory listing (for Apache: 'Options -Indexes') "
                           "and place an index.php file in upload folders.",
            evidence=listed_folders[:20],
            category="Security Misconfiguration",
            confidence="High",
            request_ids=listing_request_ids,
            attack=techniques("T1083"),
        ))

    if log_folders:
        findings.append(make_finding(
            title="Log/backup folders are exposed",
            severity="Medium",
            summary="Browsable folders that probably contain logs or backups were found.",
            impact="Store logs can contain customer or order details, creating a privacy "
                   "problem.",
            recommendation="Move logs and backups outside the public web folder.",
            evidence=log_folders[:20],
            category="Sensitive Data Exposure",
            confidence="Medium",
            request_ids=listing_request_ids,
            attack=techniques("T1083"),
        ))

    if active_svg_files:
        findings.append(make_finding(
            title="Active script content found in public SVG uploads",
            severity="High",
            summary="Publicly accessible SVG files contain script elements or event "
                    "handlers. This confirms active client-side payload content, but does "
                    "not prove that the payload ran or that the site was compromised.",
            impact="If a vulnerable plugin or administrator page embeds these files in the "
                   "site's origin, their JavaScript could run in a trusted session.",
            recommendation="Preserve copies and relevant logs, remove or quarantine the "
                           "files after evidence collection, fix the upload/sanitization "
                           "path, and investigate whether any privileged user viewed them.",
            evidence=active_svg_files[:30],
            category="Unsafe File Upload",
            confidence="Confirmed",
            request_ids=listing_request_ids + suspicious_request_ids,
            attack=techniques("T1059.007"),
        ))

    if executable_files:
        findings.append(make_finding(
            title="Server-executable file extensions found in uploads",
            severity="High",
            summary="Public directory listings showed server-executable file types in the "
                    "uploads tree. The scanner did not request them because doing so could "
                    "execute their code.",
            impact="Executable code in uploads can provide a direct path to remote command "
                   "execution when the web server allows it to run.",
            recommendation="Inspect the files from the server filesystem, preserve evidence, "
                           "disable script execution in uploads, and investigate the upload "
                           "path as a possible incident.",
            evidence=executable_files[:30],
            category="Unsafe File Upload",
            confidence="Medium",
            request_ids=listing_request_ids,
            attack=techniques("T1505.003"),
        ))

    if suspicious_files:
        findings.append(make_finding(
            title="Suspicious filenames found in uploads",
            severity="Medium",
            summary="Public directory listings showed filenames that deserve manual "
                    "inspection. A filename alone does not prove malicious content.",
            impact="If a listed file contains active payload code, it could indicate an "
                   "unsafe upload path or a compromise.",
            recommendation="Preserve the files and relevant logs, inspect their contents "
                           "safely, identify how they were uploaded, and escalate to incident "
                           "response if the contents are malicious.",
            evidence=suspicious_files[:30],
            category="Unsafe File Upload",
            confidence="Low",
            request_ids=listing_request_ids + suspicious_request_ids,
            attack=techniques("T1505.003"),
        ))

    return findings


def find_svg_script_indicators(body):
    """Return concrete active-content indicators found in SVG text."""
    indicators = []

    if re.search(r"<(?:[a-z0-9_-]+:)?script\b", body, re.IGNORECASE):
        indicators.append("script element")
    if re.search(r"\bon[a-z]+\s*=", body, re.IGNORECASE):
        indicators.append("event handler")
    if re.search(r"\bjavascript\s*:", body, re.IGNORECASE):
        indicators.append("javascript URL")
    if re.search(r"<foreignObject\b", body, re.IGNORECASE):
        indicators.append("foreignObject element")

    return indicators


def is_directory_listing(page_html):
    """Return True when a page looks like an Apache/nginx auto-index."""
    return bool(re.search(
        r"<(?:title|h1)[^>]*>\s*Index of(?:\s|/|<)",
        page_html,
        re.IGNORECASE,
    ))


def find_listing_entries(page_html):
    """Pull file/folder names out of an Apache directory-listing page.

    The page has links like <a href="photo.jpg">photo.jpg</a>. We want the
    'photo.jpg' part, but we skip the sorting links (which start with '?') and
    the 'Parent Directory' link (which starts with '/').
    """
    entries = []
    hrefs = re.findall(
        r'<a\s+[^>]*href=["\']([^"\']+)["\']',
        page_html,
        re.IGNORECASE,
    )
    for href in hrefs:
        href = html_module.unescape(href)
        parts = urlsplit(href)
        if parts.scheme or parts.netloc or parts.query or parts.fragment:
            continue

        path = unquote(parts.path)
        if not path or path in (".", "./", "..", "../"):
            continue
        if path.startswith("/") or path.startswith("../") or "/../" in path:
            continue
        # A normal auto-index links one entry at a time. Skipping nested paths
        # prevents a crafted listing from moving the scan unexpectedly.
        if "/" in path.rstrip("/"):
            continue
        if path not in entries:
            entries.append(path)
    return entries


# ---------------------------------------------------------------------------
# Check 8: Does the login page have any brute-force protection?
# ---------------------------------------------------------------------------
def check_login_protection(base_url, info, client):
    findings = []
    if not info.get("is_wordpress"):
        return findings

    response = client.fetch(site_url(base_url, "wp-login.php"))
    page = response["body"].lower()

    # We look for clues that some protection is installed.
    protections = []
    if "recaptcha" in page:
        protections.append("reCAPTCHA")
    if "limit-login" in page or "too many" in page:
        protections.append("login rate-limiting")
    if "two-factor" in page or "authenticator" in page:
        protections.append("two-factor login")
    if "wordfence" in page:
        protections.append("Wordfence")

    # If we found NONE, that is worth reporting.
    if not protections:
        findings.append(make_finding(
            title="No visible login challenge was detected",
            severity="Info",
            summary="The public login page did not show a recognizable CAPTCHA, security "
                    "plugin marker, or two-factor prompt.",
            impact="An external page check cannot confirm server-side rate limiting, a WAF, "
                   "or a second factor that appears after password entry.",
            recommendation="Verify rate limiting and administrator two-factor authentication "
                           "from the server or WordPress dashboard.",
            evidence=["No recognizable protection marker was visible on wp-login.php"],
            category="Authentication Controls",
            confidence="Low",
            request_ids=[response["request_id"]],
            attack=techniques("T1110.001"),
        ))
    return findings


# ---------------------------------------------------------------------------
# Check 9: Does the site keep visitors on HTTPS?
# ---------------------------------------------------------------------------
def check_transport_security(base_url, info, _client):
    findings = []
    requested_scheme = urlsplit(base_url).scheme.lower()
    final_scheme = urlsplit(info.get("home_final_url", base_url)).scheme.lower()

    if requested_scheme == "http" and final_scheme != "https":
        findings.append(make_finding(
            title="HTTPS is not enforced for the public site",
            severity="Medium",
            summary="The HTTP site remained on HTTP instead of redirecting visitors to "
                    "an HTTPS address.",
            impact="Traffic and credentials can be exposed or modified on untrusted "
                   "networks when the site is used without TLS.",
            recommendation="Install a valid certificate, redirect all HTTP requests to "
                           "HTTPS, and update WordPress and canonical URLs.",
            evidence=[
                "Requested: " + base_url,
                "Final URL: " + info.get("home_final_url", base_url),
            ],
            category="Transport Security",
            confidence="High",
            request_ids=info_request_ids(info, "home"),
            attack=techniques("T1040", "T1557"),
        ))

    return findings


# ---------------------------------------------------------------------------
# Check 10: Are common browser defense-in-depth headers present?
# ---------------------------------------------------------------------------
def check_security_headers(base_url, info, _client):
    findings = []
    headers = info.get("home_headers", {})
    final_scheme = urlsplit(info.get("home_final_url", base_url)).scheme.lower()

    missing = []
    if "content-security-policy" not in headers:
        missing.append("Content-Security-Policy")
    if (
        "x-frame-options" not in headers and
        "frame-ancestors" not in headers.get("content-security-policy", "")
    ):
        missing.append("X-Frame-Options or CSP frame-ancestors")
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        missing.append("X-Content-Type-Options: nosniff")
    if "referrer-policy" not in headers:
        missing.append("Referrer-Policy")
    if final_scheme == "https" and "strict-transport-security" not in headers:
        missing.append("Strict-Transport-Security")

    if missing:
        findings.append(make_finding(
            title="Browser security headers are incomplete",
            severity="Low",
            summary="The homepage response is missing one or more common browser "
                    "defense-in-depth headers.",
            impact="Missing headers do not prove an exploitable flaw, but they can increase "
                   "the impact of content injection, framing, or MIME confusion issues.",
            recommendation="Add the missing headers after testing them in staging. Start "
                           "Content-Security-Policy in report-only mode before enforcement.",
            evidence=["Missing: " + header for header in missing],
            category="Security Misconfiguration",
            confidence="High",
            request_ids=info_request_ids(info, "home"),
            attack=techniques("T1539"),
        ))

    return findings


# ---------------------------------------------------------------------------
# The master list of checks. The scanner runs these in order.
# Each item is a pair: (short id, the function to call).
# ---------------------------------------------------------------------------
ALL_CHECKS = [
    ("server-banner", check_server_banner),
    ("wp-version", check_wp_version),
    ("components", check_components),
    ("user-enum", check_user_enumeration),
    ("xmlrpc", check_xmlrpc),
    ("exposed-files", check_exposed_files),
    ("dir-listing", check_directory_listing),
    ("login-protection", check_login_protection),
    ("transport-security", check_transport_security),
    ("security-headers", check_security_headers),
]
