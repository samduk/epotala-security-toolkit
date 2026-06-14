"""
detect.py
=========

Before running our checks, we gather a few basic facts about the website:

  * what web server it runs (from the "Server" header)
  * whether it is a WordPress site
  * the WordPress version (if we can read it)
  * which plugin and theme references are publicly visible

We collect these once and put them in a dictionary called `info`. Each check
can then look at `info` instead of fetching the same pages again.
"""

import json
import re

from .http_helper import site_url


def collect_info(base_url, client):
    """Return a dictionary of basic facts about the site."""

    info = {
        "server": "unknown",
        "reachable": False,
        "home_status": 0,
        "home_error": "",
        "is_wordpress": False,
        "wp_version": "",
        "components": {},   # slug -> {"kind": "plugin"/"theme", "version": "1.2.3"}
        "users": [],        # public author names/slugs we managed to read
        "home_final_url": "",
        "home_headers": {},
        "evidence_requests": {
            "home": [],
            "wp_version": [],
            "components": [],
            "users": [],
        },
    }

    # --- 1) Fetch the home page and read the "Server" header. ---
    home = client.fetch(site_url(base_url, ""))
    info["reachable"] = home["status"] > 0
    info["home_status"] = home["status"]
    info["home_error"] = home["error"] or ""
    info["server"] = home["headers"].get("server", "unknown")
    info["home_final_url"] = home["final_url"]
    info["home_headers"] = selected_response_headers(home["headers"])
    info["evidence_requests"]["home"].append(home["request_id"])

    if not info["reachable"]:
        return info

    # --- 2) Is this WordPress? Look for WordPress-specific markers. ---
    home_body = home["body"].lower()
    if "wp-content/" in home_body or "wp-includes/" in home_body:
        info["is_wordpress"] = True

    if not info["is_wordpress"]:
        login = client.fetch(site_url(base_url, "wp-login.php"))
        login_body = login["body"].lower()
        info["evidence_requests"]["home"].append(login["request_id"])
        if 'id="loginform"' in login_body or 'name="log"' in login_body:
            info["is_wordpress"] = True

    if not info["is_wordpress"]:
        api = client.fetch(site_url(base_url, "wp-json/"))
        info["evidence_requests"]["home"].append(api["request_id"])
        try:
            api_data = json.loads(api["body"])
        except (TypeError, ValueError):
            api_data = {}
        if isinstance(api_data, dict) and "namespaces" in api_data:
            namespaces = api_data.get("namespaces", [])
            if isinstance(namespaces, list) and "wp/v2" in namespaces:
                info["is_wordpress"] = True

    if not info["is_wordpress"]:
        return info  # Nothing more to detect on a non-WordPress site.

    # --- 3) Try to read the WordPress version. ---
    version, request_ids = detect_wp_version(base_url, client)
    info["wp_version"] = version
    info["evidence_requests"]["wp_version"] = request_ids

    # --- 4) Find public plugin/theme references and reported versions. ---
    components, request_ids = detect_components(base_url, home["body"], client)
    info["components"] = components
    info["evidence_requests"]["components"] = request_ids

    # --- 5) Try to read usernames from the public REST API. ---
    users, request_ids = detect_users(base_url, client)
    info["users"] = users
    info["evidence_requests"]["users"] = request_ids

    return info


def selected_response_headers(headers):
    """Keep headers useful for security checks without copying everything."""
    useful = (
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    )
    return {key: headers[key] for key in useful if key in headers}


def detect_wp_version(base_url, client):
    """Look for the WordPress version in the RSS feed, then the readme file."""
    request_ids = []

    # The RSS feed often contains <generator>https://wordpress.org/?v=6.5</generator>
    feed = client.fetch(site_url(base_url, "feed/"))
    request_ids.append(feed["request_id"])
    match = re.search(r"wordpress\.org/\?v=([0-9.]+)", feed["body"])
    if match:
        return match.group(1), request_ids

    # Otherwise the readme.html page usually says "Version 6.5".
    readme = client.fetch(site_url(base_url, "readme.html"))
    request_ids.append(readme["request_id"])
    match = re.search(r"[Vv]ersion\s+([0-9]+\.[0-9.]+)", readme["body"])
    if match:
        return match.group(1), request_ids

    return "", request_ids


def detect_components(base_url, home_html, client):
    """Find plugin/theme folders mentioned on the site and read their versions."""
    components = {}
    request_ids = []

    # WordPress loads files from paths like:
    #   /wp-content/plugins/woocommerce/...
    #   /wp-content/themes/twentytwentyfive/...
    # We scan the home page AND the shop page for those paths.
    pages_to_scan = [home_html]
    shop = client.fetch(site_url(base_url, "shop/"))
    request_ids.append(shop["request_id"])
    pages_to_scan.append(shop["body"])

    for html in pages_to_scan:
        for folder, slug in re.findall(r"/wp-content/(plugins|themes)/([a-z0-9_-]+)", html):
            kind = "plugin" if folder == "plugins" else "theme"
            if slug not in components:
                components[slug] = {"kind": kind, "version": "unknown"}

    # Now try to read each component's version from its readme/style file.
    for slug, details in components.items():
        version, version_request_ids = read_component_version(
            base_url,
            slug,
            details["kind"],
            client,
        )
        details["version"] = version
        request_ids.extend(version_request_ids)

    return components, request_ids


def read_component_version(base_url, slug, kind, client):
    """Read a plugin's readme.txt or a theme's style.css to find its version."""
    folder = "plugins" if kind == "plugin" else "themes"
    request_ids = []

    # Most plugins ship a readme.txt with a line like "Stable tag: 1.2.3".
    readme_url = site_url(
        base_url,
        "wp-content/" + folder + "/" + slug + "/readme.txt",
    )
    readme = client.fetch(readme_url)
    request_ids.append(readme["request_id"])
    match = re.search(
        r"Stable tag:\s*([0-9][0-9.]*)",
        readme["body"],
        re.IGNORECASE,
    )
    if readme["status"] == 200 and match:
        return match.group(1), request_ids

    # Themes keep their version in style.css instead ("Version: 1.4").
    if kind == "theme":
        style_url = site_url(
            base_url,
            "wp-content/themes/" + slug + "/style.css",
        )
        style = client.fetch(style_url)
        request_ids.append(style["request_id"])
        match = re.search(r"Version:\s*([0-9][0-9.]*)", style["body"], re.IGNORECASE)
        if style["status"] == 200 and match:
            return match.group(1), request_ids

    return "unknown", request_ids


def detect_users(base_url, client):
    """Try to read public author names/slugs from the WordPress REST API."""
    authors = []
    response = client.fetch(site_url(base_url, "wp-json/wp/v2/users"))
    if response["status"] == 200:
        try:
            people = json.loads(response["body"])
        except (ValueError, TypeError):
            people = []

        if isinstance(people, list):
            for person in people:
                if not isinstance(person, dict):
                    continue
                # The REST "slug" is a public author slug. It may resemble the
                # login name, but an external scan cannot prove that it is one.
                authors.append(
                    f"id {person.get('id')}: {person.get('name')} "
                    f"(public slug: {person.get('slug')})"
                )
    return authors, [response["request_id"]]
