"""Regression tests for epxtool's commercial safety and audit controls."""

import io
import gzip
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

TOOL_FOLDER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import sys

sys.path.insert(0, TOOL_FOLDER)

from epxtool.checks import (  # noqa: E402
    check_exposed_files,
    check_security_headers,
    check_transport_security,
    check_xmlrpc,
    find_listing_entries,
    find_svg_script_indicators,
    is_directory_listing,
    looks_like_sensitive_file,
)
from epxtool.attack import technique, techniques  # noqa: E402
from epxtool import cve  # noqa: E402
from epxtool.detect import detect_users  # noqa: E402
from epxtool.findings import make_finding  # noqa: E402
from epxtool.http_helper import (  # noqa: E402
    MAX_RESPONSE_BYTES,
    HttpClient,
    SameSiteRedirectHandler,
    comparable_hostname,
    read_limited,
)
from epxtool.io_utils import verify_artifact, write_artifact  # noqa: E402
from epxtool.forensics import (  # noqa: E402
    MAX_LINE_BYTES,
    collect_evidence,
    iter_bounded_lines,
    run_forensics,
)
from epxtool.forensics_report import (  # noqa: E402
    build_forensics_html,
    build_forensics_markdown,
)
from epxtool.forensics_schema import validate_forensics_result  # noqa: E402
from epxtool.report import build_html, build_markdown, overall_posture  # noqa: E402
from epxtool.scanner import run_scan, stable_finding_id, tidy_target  # noqa: E402
from epxtool.schema import SCHEMA_VERSION, validate_attack, validate_result  # noqa: E402


def response(status=200, body="", final_url="https://example.com/", request_id="REQ-0001"):
    """Build the simple response dictionary returned by HttpClient.fetch()."""
    return {
        "request_id": request_id,
        "status": status,
        "body": body,
        "byte_length": len(body.encode("utf-8")),
        "truncated": False,
        "final_url": final_url,
        "headers": {},
        "error": None,
    }


class FakeClient:
    """Return predefined responses without touching the network."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.position = 0

    def fetch(self, url, method="GET", data=None, content_type=None):
        if self.position >= len(self.responses):
            item = response(status=404, final_url=url)
        else:
            item = dict(self.responses[self.position])
        self.position += 1
        item["request_id"] = "REQ-" + str(self.position).zfill(4)
        item["final_url"] = item.get("final_url") or url
        return item


def authorization():
    """Return a complete test authorization record."""
    return {
        "confirmed": True,
        "reference": "SOW-TEST-001",
        "operator": "Test Operator",
        "client": "Example Client",
        "confirmed_at": "2026-06-14T00:00:00Z",
    }


def discovered_info():
    """Return a complete WordPress discovery result for scanner tests."""
    return {
        "server": "Apache/2.4.62",
        "reachable": True,
        "home_status": 200,
        "home_error": "",
        "is_wordpress": True,
        "wp_version": "6.8.1",
        "components": {},
        "users": [],
        "home_final_url": "https://example.com/",
        "home_headers": {},
        "evidence_requests": {
            "home": [],
            "wp_version": [],
            "components": [],
            "users": [],
        },
    }


def valid_result():
    """Return a minimal current-schema result for report tests."""
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": "1.0.0",
        "scan_id": "11111111-1111-4111-8111-111111111111",
        "status": "complete",
        "target": "https://example.com",
        "started_at": "2026-06-14T00:00:00Z",
        "finished_at": "2026-06-14T00:00:01Z",
        "authorization": authorization(),
        "scope": {
            "mode": "external-read-only",
            "base_url": "https://example.com",
            "hostname": "example.com",
            "path": "/",
            "methods": ["GET", "POST"],
            "selected_checks": [],
        },
        "settings": {
            "timeout_seconds": 10,
            "verify_tls": True,
            "delay_seconds": 0.1,
            "max_requests": 100,
            "max_response_bytes": MAX_RESPONSE_BYTES,
        },
        "info": discovered_info(),
        "checks": [{
            "id": "discovery",
            "status": "completed",
            "started_at": "2026-06-14T00:00:00Z",
            "finished_at": "2026-06-14T00:00:01Z",
            "findings_count": 0,
            "request_ids": [],
            "errors": [],
        }],
        "findings": [],
        "errors": [],
        "statistics": {
            "requests_total": 0,
            "network_requests": 0,
            "request_errors": 0,
            "bytes_received": 0,
            "truncated_responses": 0,
            "duration_seconds": 1.0,
            "findings_total": 0,
        },
        "evidence": {"requests": []},
    }


class ScannerTests(unittest.TestCase):
    def test_tidy_target_accepts_a_subfolder(self):
        self.assertEqual(
            tidy_target("example.com/blog/"),
            "http://example.com/blog",
        )

    def test_tidy_target_rejects_query_strings(self):
        with self.assertRaises(ValueError):
            tidy_target("https://example.com/?author=1")

    def test_tidy_target_rejects_non_http_schemes(self):
        with self.assertRaises(ValueError):
            tidy_target("ftp://example.com")

    def test_dead_target_is_inconclusive(self):
        info = {"reachable": False, "is_wordpress": False}
        posture = overall_posture([], info, [], "failed")
        self.assertIn("Inconclusive", posture)

    @patch("epxtool.scanner.detect.collect_info")
    def test_detection_error_becomes_a_failed_result(self, mock_collect):
        mock_collect.side_effect = ValueError("unexpected response")
        result = run_scan(
            "https://example.com",
            authorization=authorization(),
            delay=0,
        )
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any(
            "basic information gathering failed" in error
            for error in result["errors"]
        ))
        validate_result(result)

    @patch("epxtool.scanner.detect.collect_info")
    def test_successful_scan_has_stable_ids_and_a_valid_schema(self, mock_collect):
        mock_collect.return_value = discovered_info()

        def sample_check(base_url, info, client):
            return [make_finding(
                title="Sample finding",
                severity="Low",
                summary="A test finding.",
                category="Testing",
                confidence="High",
            )]

        with patch("epxtool.scanner.ALL_CHECKS", [("sample", sample_check)]):
            first = run_scan(
                "https://example.com",
                authorization=authorization(),
                delay=0,
            )
            second = run_scan(
                "https://example.com",
                authorization=authorization(),
                delay=0,
            )

        self.assertEqual(first["status"], "complete")
        self.assertEqual(first["findings"][0]["id"], second["findings"][0]["id"])
        self.assertEqual(
            first["findings"][0]["id"],
            stable_finding_id("sample", "Sample finding"),
        )
        validate_result(first)

    @patch("epxtool.scanner.detect.collect_info")
    def test_missing_authorization_marks_scan_incomplete(self, mock_collect):
        mock_collect.return_value = discovered_info()
        with patch("epxtool.scanner.ALL_CHECKS", []):
            result = run_scan("https://example.com", delay=0)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("authorization confirmation", result["errors"][0])


class DetectionTests(unittest.TestCase):
    def test_rest_slug_is_not_labelled_as_a_login(self):
        client = FakeClient([
            response(body='[{"id":1,"name":"Editor","slug":"editor"}]'),
        ])
        authors, request_ids = detect_users("https://example.com", client)
        self.assertEqual(authors, ["id 1: Editor (public slug: editor)"])
        self.assertEqual(request_ids, ["REQ-0001"])

    def test_unexpected_rest_object_does_not_crash(self):
        client = FakeClient([
            response(body='{"code":"rest_forbidden"}'),
        ])
        authors, request_ids = detect_users("https://example.com", client)
        self.assertEqual(authors, [])
        self.assertEqual(request_ids, ["REQ-0001"])


class CheckTests(unittest.TestCase):
    def test_sensitive_file_check_rejects_a_normal_html_page(self):
        self.assertFalse(
            looks_like_sensitive_file(".env", "<html><h1>Home</h1></html>")
        )
        self.assertTrue(
            looks_like_sensitive_file(".env", "DB_HOST=localhost\nDB_NAME=site\n")
        )

    def test_soft_404_pages_are_not_exposed_files(self):
        client = FakeClient([
            response(body="<html><h1>Not found</h1></html>")
            for number in range(8)
        ])
        findings = check_exposed_files(
            "https://example.com",
            {"is_wordpress": True},
            client,
        )
        self.assertEqual(findings, [])

    def test_xmlrpc_needs_exact_method_names(self):
        client = FakeClient([
            response(body="<html>This page mentions pingback and multicall.</html>"),
        ])
        findings = check_xmlrpc(
            "https://example.com",
            {"is_wordpress": True},
            client,
        )
        self.assertEqual(findings, [])

        client = FakeClient([
            response(body=(
                "<string>pingback.ping</string>"
                "<string>system.multicall</string>"
            )),
        ])
        findings = check_xmlrpc(
            "https://example.com",
            {"is_wordpress": True},
            client,
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], "High")

    def test_directory_parser_skips_parent_and_nested_paths(self):
        page = (
            "<title>Index of /uploads</title>"
            '<a href="../">Parent</a>'
            '<a href="safe.jpg">safe.jpg</a>'
            '<a href="folder/">folder</a>'
            '<a href="folder/hidden.php">nested</a>'
            '<a href="%2e%2e/secret">encoded traversal</a>'
        )
        self.assertTrue(is_directory_listing(page))
        self.assertEqual(find_listing_entries(page), ["safe.jpg", "folder/"])

    def test_svg_script_indicators_use_file_content(self):
        active_svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">'
            "<script>alert(2)</script></svg>"
        )
        self.assertEqual(
            find_svg_script_indicators(active_svg),
            ["script element", "event handler"],
        )
        self.assertEqual(
            find_svg_script_indicators("<svg><rect width='10'/></svg>"),
            [],
        )

    def test_http_without_redirect_is_a_transport_finding(self):
        info = discovered_info()
        info["home_final_url"] = "http://example.com/"
        findings = check_transport_security(
            "http://example.com",
            info,
            FakeClient([]),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["category"], "Transport Security")

    def test_missing_browser_headers_are_low_severity(self):
        info = discovered_info()
        findings = check_security_headers(
            "https://example.com",
            info,
            FakeClient([]),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Low")


class HttpTests(unittest.TestCase):
    def test_response_reader_has_a_size_limit(self):
        stream = io.BytesIO(b"a" * (MAX_RESPONSE_BYTES + 50))
        body, truncated = read_limited(stream)
        self.assertEqual(len(body), MAX_RESPONSE_BYTES)
        self.assertTrue(truncated)

    def test_www_redirect_is_treated_as_the_same_hostname(self):
        self.assertEqual(
            comparable_hostname("https://www.example.com/path"),
            comparable_hostname("http://example.com/"),
        )

    def test_request_budget_is_recorded_without_network_access(self):
        client = HttpClient(
            "https://example.com",
            delay=0,
            max_requests=0,
        )
        result = client.fetch("https://example.com/")
        self.assertEqual(result["status"], 0)
        self.assertIn("request limit reached", result["error"])
        self.assertEqual(client.trace[0]["id"], "REQ-0001")

    def test_https_downgrade_redirect_is_blocked(self):
        handler = SameSiteRedirectHandler("https://example.com")
        request = __import__("urllib.request").request.Request(
            "https://example.com/"
        )
        with self.assertRaises(Exception):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "http://example.com/",
            )


class ArtifactTests(unittest.TestCase):
    def test_artifact_digest_detects_tampering(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "scan.json")
            digest = write_artifact(path, '{"ok": true}\n')
            actual, verified = verify_artifact(path)
            self.assertEqual(digest, actual)
            self.assertTrue(verified)

            Path(path).write_text('{"ok": false}\n', encoding="utf-8")
            actual, verified = verify_artifact(path)
            self.assertFalse(verified)

    def test_artifacts_are_private_by_default(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "scan.json")
            write_artifact(path, "{}\n")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(path + ".sha256").st_mode & 0o777, 0o600)


class ForensicsTests(unittest.TestCase):
    @staticmethod
    def log_line(ip, timestamp, method, target, status=200, size=1096):
        return (
            ip + " - - [" + timestamp + '] "' + method + " " + target +
            ' HTTP/1.1" ' + str(status) + " " + str(size) +
            ' "-" "test-agent"\n'
        )

    def test_bounded_line_reader_does_not_retain_a_large_line(self):
        stream = io.BytesIO(b"a" * (MAX_LINE_BYTES * 2) + b"\nnext\n")
        lines = list(iter_bounded_lines(stream))
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0][2])
        self.assertLessEqual(len(lines[0][1]), MAX_LINE_BYTES)
        self.assertEqual(lines[1][1], b"next\n")

    def test_gzip_logs_are_read_and_duplicate_content_is_skipped(self):
        with tempfile.TemporaryDirectory() as folder:
            plain = Path(folder) / "access.log"
            zipped = Path(folder) / "access.log.gz"
            content = self.log_line(
                "192.0.2.10", "21/Apr/2026:01:00:00 +0000",
                "GET", "/", 200, 100,
            ).encode()
            plain.write_bytes(content)
            with gzip.open(zipped, "wb") as handle:
                handle.write(content)
            result = run_forensics(
                folder, "CASE-1", site="example.test",
                authorization_reference="SOW-1", operator="Analyst", client="Client",
            )
            validate_forensics_result(result)
            self.assertEqual(result["statistics"]["parsed_log_lines"], 1)
            self.assertEqual(result["statistics"]["duplicate_items"], 1)

    def test_archive_member_traversal_is_rejected_without_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            archive_path = Path(folder) / "bad.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../outside.php", "<?php echo 1;")
            manifests, items, errors = collect_evidence(folder)
            self.assertEqual(len(manifests), 1)
            self.assertEqual(items, [])
            self.assertTrue(errors and "unsafe archive member path" in errors[0])
            self.assertFalse((Path(folder).parent / "outside.php").exists())

    def test_logs_create_timeline_and_distinguish_attempts_from_exploitation(self):
        with tempfile.TemporaryDirectory() as folder:
            lines = []
            for second in range(30):
                lines.append(self.log_line(
                    "192.0.2.20",
                    "21/Apr/2026:01:00:" + str(second).zfill(2) + " +0000",
                    "POST", "/wp-login.php", 302, 0,
                ))
            for number in range(25):
                lines.append(self.log_line(
                    "192.0.2.30",
                    "21/Apr/2026:01:01:" + str(number).zfill(2) + " +0000",
                    "GET", "/random" + str(number) + ".php", 200, 1096,
                ))
            lines.extend([
                self.log_line(
                    "192.0.2.40", "21/Apr/2026:01:02:00 +0000", "POST",
                    "/wp-includes/a/b/c/index.php", 200, 113,
                ),
                self.log_line(
                    "192.0.2.41", "21/Apr/2026:01:02:01 +0000", "GET",
                    "/wp-includes/a/b/c/index.php?control=yes", 200, 177,
                ),
            ])
            (Path(folder) / "access.log").write_text("".join(lines), encoding="utf-8")
            result = run_forensics(
                folder, "CASE-2", site="example.test",
                authorization_reference="SOW-2", operator="Analyst", client="Client",
            )
            titles = {item["title"] for item in result["findings"]}
            self.assertIn("Automated WordPress login attacks", titles)
            self.assertIn("High-volume web-shell discovery activity", titles)
            self.assertIn("Likely interaction with a hidden PHP backdoor", titles)
            hidden = next(
                item for item in result["findings"]
                if item["title"] == "Likely interaction with a hidden PHP backdoor"
            )
            self.assertEqual(hidden["confidence"], "High")
            validate_forensics_result(result)

    def test_static_php_is_classified_without_execution_and_reports_render(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "upload.php").write_text(
                "<?php move_uploaded_file($_FILES['f']['tmp_name'], '../x.php');",
                encoding="utf-8",
            )
            (Path(folder) / "dump.sql").write_text(
                "INSERT INTO posts VALUES (1, '<script src=\"normal.js\"></script>');\n",
                encoding="utf-8",
            )
            result = run_forensics(
                folder, "CASE-3", site="example.test",
                authorization_reference="SOW-3", operator="Analyst", client="Client",
            )
            self.assertEqual(result["assessment"]["compromise_status"], "confirmed")
            self.assertEqual(result["assessment"]["database_injection"], "not-found")
            markdown = build_forensics_markdown(result)
            html_report = build_forensics_html(result)
            self.assertIn("Incident timeline", markdown)
            self.assertIn("Malicious server-side artifacts", markdown)
            self.assertIn("Incident timeline", html_report)
            json.dumps(result)


class SchemaTests(unittest.TestCase):
    def test_valid_result_passes(self):
        validate_result(valid_result())

    def test_result_rejects_missing_fields(self):
        with self.assertRaises(ValueError):
            validate_result({"target": "https://example.com"})

    def test_unknown_request_reference_is_rejected(self):
        result = valid_result()
        result["checks"][0]["request_ids"] = ["REQ-9999"]
        with self.assertRaises(ValueError):
            validate_result(result)


class ReportTests(unittest.TestCase):
    def test_markdown_escapes_remote_html(self):
        result = valid_result()
        result["info"]["server"] = "<script>alert(1)</script>"
        report = build_markdown(result)
        self.assertNotIn("<script>", report)
        self.assertIn("&lt;script&gt;", report)

    def test_unreviewed_report_is_clearly_a_draft(self):
        report = build_markdown(valid_result())
        self.assertIn("AUTOMATED DRAFT", report)
        self.assertIn("review required", report.lower())
        self.assertNotIn("—", report)

    def test_reviewed_html_names_the_analyst(self):
        result = valid_result()
        result["_report_context"] = {
            "reviewed_by": "Security Analyst",
            "client_name": "Client",
            "report_id": "REP-001",
            "source_sha256": "a" * 64,
            "integrity_status": "verified",
        }
        report = build_html(result)
        self.assertIn("Reviewed by Security Analyst", report)
        self.assertIn("REP-001", report)
        self.assertIn("verified", report)


class AttackMappingTests(unittest.TestCase):
    def test_technique_reference_has_canonical_fields_and_url(self):
        ref = technique("T1110.001")
        self.assertEqual(ref["id"], "T1110.001")
        self.assertEqual(ref["tactic"], "Credential Access")
        self.assertEqual(
            ref["url"],
            "https://attack.mitre.org/techniques/T1110/001/",
        )

    def test_unknown_technique_is_rejected(self):
        with self.assertRaises(KeyError):
            technique("T9999")

    def test_real_check_tags_findings_with_attack(self):
        info = {"is_wordpress": True, "home_final_url": "http://example.com/"}
        findings = check_transport_security("http://example.com", info, FakeClient([]))
        self.assertTrue(findings)
        ids = {tech["id"] for tech in findings[0]["attack"]}
        self.assertEqual(ids, {"T1040", "T1557"})

    def test_schema_rejects_malformed_attack_id(self):
        bad = [{"id": "nope", "name": "x", "tactic": "y", "url": "z"}]
        with self.assertRaises(ValueError):
            validate_attack(bad, "finding 1")

    def test_attack_survives_validation_in_a_full_result(self):
        result = valid_result()
        finding = make_finding(
            title="Sample finding",
            severity="Low",
            summary="A test finding.",
            category="Testing",
            confidence="High",
            attack=techniques("T1110.001"),
        )
        finding["id"] = "EPX-ABCDEF0123"
        finding["check_id"] = "discovery"
        result["findings"].append(finding)
        result["statistics"]["findings_total"] = 1
        validate_result(result)

    def test_reports_render_the_attack_mapping(self):
        result = valid_result()
        finding = make_finding(
            title="HTTPS is not enforced for the public site",
            severity="Medium",
            summary="Plain HTTP only.",
            category="Transport Security",
            confidence="High",
            attack=techniques("T1040", "T1557"),
        )
        finding["id"] = "EPX-ABCDEF0123"
        finding["check_id"] = "discovery"
        result["findings"].append(finding)
        result["statistics"]["findings_total"] = 1

        markdown = build_markdown(result)
        self.assertIn("MITRE ATT&CK mapping", markdown)
        self.assertIn("T1040 Network Sniffing", markdown)

        html_report = build_html(result)
        self.assertIn("MITRE ATT&amp;CK mapping", html_report)
        self.assertIn("https://attack.mitre.org/techniques/T1557/", html_report)
        self.assertIn('<div class="chips"><span class="chip"', html_report)
        self.assertNotIn('<div class="chips"><a class="attack"', html_report)
        self.assertIn("Credential Access</td>\n<td><a", html_report)


class CveCorrelationTests(unittest.TestCase):
    def test_version_comparison_states(self):
        self.assertEqual(cve.version_is_affected("3.2.36", "3.3.0"), "affected")
        self.assertEqual(cve.version_is_affected("3.3.0", "3.3.0"), "fixed")
        self.assertEqual(cve.version_is_affected("unknown", "3.3.0"), "unknown")
        self.assertEqual(cve.version_is_affected("3.2.0", ""), "affected")

    def test_correlate_builds_a_capped_candidate_finding(self):
        payload = {
            "booking-calendar": {
                "vulnerabilities": [{
                    "title": "SQL Injection",
                    "fixed_in": "3.3.0",
                    "references": {"cve": ["2024-1111"]},
                    "cvss": {"score": "8.8"},
                }]
            }
        }

        def fake_fetcher(path, api_key, timeout, verify_tls):
            self.assertIn("booking-calendar", path)
            return 200, payload, ""

        findings, errors = cve.correlate(
            "",
            {"booking-calendar": {"kind": "plugin", "version": "3.2.36"}},
            "test-key",
            fetcher=fake_fetcher,
        )
        self.assertEqual(errors, [])
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["severity"], "High")  # CVSS 8.8
        self.assertEqual(finding["confidence"], "Medium")  # never Confirmed
        self.assertEqual(finding["category"], "Vulnerable Component")
        self.assertIn("CVE-2024-1111", finding["evidence"][0])
        self.assertEqual({t["id"] for t in finding["attack"]}, {"T1190"})

    def test_correlate_skips_patched_versions_and_reports_feed_errors(self):
        def patched_fetcher(path, api_key, timeout, verify_tls):
            return 200, {"woo": {"vulnerabilities": [
                {"title": "old", "fixed_in": "1.0.0", "references": {"cve": ["1"]}}
            ]}}, ""

        findings, errors = cve.correlate(
            "", {"woo": {"kind": "plugin", "version": "2.0.0"}},
            "k", fetcher=patched_fetcher,
        )
        self.assertEqual(findings, [])
        self.assertEqual(errors, [])

        def broken_fetcher(path, api_key, timeout, verify_tls):
            return 0, None, "vulnerability feed request failed: timeout"

        findings, errors = cve.correlate(
            "", {"woo": {"kind": "plugin", "version": "2.0.0"}},
            "k", fetcher=broken_fetcher,
        )
        self.assertEqual(findings, [])
        self.assertTrue(errors and "woo:" in errors[0])

    def test_correlate_requires_a_key(self):
        findings, errors = cve.correlate("", {}, "")
        self.assertEqual(findings, [])
        self.assertIn("no API key", errors[0])

    @patch("epxtool.scanner.detect.collect_info")
    @patch("epxtool.cve.default_fetcher")
    def test_scan_with_cve_source_is_valid_and_adds_findings(
        self, mock_fetcher, mock_collect,
    ):
        info = discovered_info()
        info["wp_version"] = ""
        info["components"] = {"booking-calendar": {"kind": "plugin", "version": "3.2.36"}}
        mock_collect.return_value = info
        mock_fetcher.return_value = (200, {
            "booking-calendar": {"vulnerabilities": [{
                "title": "SQLi", "fixed_in": "3.3.0",
                "references": {"cve": ["2024-1111"]}, "cvss": {"score": "9.1"},
            }]}
        }, "")

        with patch("epxtool.scanner.ALL_CHECKS", []):
            result = run_scan(
                "https://example.com",
                authorization=authorization(),
                delay=0,
                cve_source="wpscan",
                cve_api_key="test-key",
            )

        self.assertEqual(result["status"], "complete")
        cve_findings = [f for f in result["findings"]
                        if f["check_id"] == "cve-correlation"]
        self.assertEqual(len(cve_findings), 1)
        self.assertEqual(cve_findings[0]["severity"], "Critical")  # CVSS 9.1
        self.assertIn("cve-correlation", result["scope"]["selected_checks"])
        validate_result(result)


if __name__ == "__main__":
    unittest.main()
