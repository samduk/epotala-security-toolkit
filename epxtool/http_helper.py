"""
http_helper.py
==============

A tiny helper for downloading a web page.

The whole toolkit needs to "ask a website for a page" over and over again.
Instead of repeating the same urllib code everywhere, we write ONE function
called `fetch()` and use it everywhere.

`fetch()` always returns a plain dictionary that looks like this:

    {
        "status": 200,             # the HTTP status code (200 = OK, 404 = not found)
        "body": "<html>...",       # the page text
        "byte_length": 1234,       # bytes read (responses are capped at 2 MB)
        "truncated": False,         # True when the response exceeded that cap
        "final_url": "http://...", # where we ended up (after any redirects)
        "headers": {...},          # response headers, keys are lower-cased
        "error": None,             # a message if something went wrong, else None
    }

Returning a dictionary (instead of crashing) means one broken request can never
stop the whole scan.
"""

import ssl
import hashlib
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from . import __version__

# A short label we send so the website's logs show who is visiting.
USER_AGENT = "epxtool/" + __version__ + " (authorized security assessment)"

# Do not let one unexpectedly large page use all available memory.
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def site_url(base_url, path):
    """Join a site address and a relative path.

    This also supports WordPress installations in a subfolder, for example:
    site_url("https://example.com/blog", "wp-login.php")
    """
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def comparable_hostname(url):
    """Return a hostname suitable for redirect-scope comparisons."""
    hostname = (urlsplit(url).hostname or "").lower().rstrip(".")
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def explicit_nonstandard_port(url):
    """Return an explicitly configured non-standard port, or None."""
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        return None
    if port and port not in (80, 443):
        return port
    return None


class SameSiteRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow normal redirects without leaving the authorized web scope."""

    def __init__(self, scope_url):
        super().__init__()
        self.scope_hostname = comparable_hostname(scope_url)
        self.scope_scheme = urlsplit(scope_url).scheme.lower()
        self.scope_port = explicit_nonstandard_port(scope_url)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_parts = urlsplit(newurl)
        if comparable_hostname(newurl) != self.scope_hostname:
            raise urllib.error.URLError(
                "redirect blocked because it leaves the authorized hostname: " + newurl
            )
        if self.scope_scheme == "https" and new_parts.scheme.lower() == "http":
            raise urllib.error.URLError(
                "redirect blocked because it downgrades HTTPS to HTTP: " + newurl
            )
        if self.scope_port and explicit_nonstandard_port(newurl) != self.scope_port:
            raise urllib.error.URLError(
                "redirect blocked because it changes the authorized port: " + newurl
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_limited(response, max_bytes=MAX_RESPONSE_BYTES):
    """Read at most `max_bytes` and say whether data was truncated."""
    body = response.read(max_bytes + 1)
    truncated = len(body) > max_bytes
    return body[:max_bytes], truncated


def utc_now_text():
    """Return a current UTC timestamp suitable for evidence records."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class HttpClient:
    """Bounded HTTP client with an audit trail for one authorized target."""

    def __init__(
        self,
        base_url,
        timeout=10,
        verify_tls=True,
        delay=0.1,
        max_requests=100,
        max_response_bytes=MAX_RESPONSE_BYTES,
    ):
        self.base_url = base_url
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.delay = delay
        self.max_requests = max_requests
        self.max_response_bytes = max_response_bytes
        self.requests_made = 0
        self.last_request_started = 0.0
        self.trace = []

        ssl_context = ssl.create_default_context()
        if not verify_tls:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        self.opener = urllib.request.build_opener(
            SameSiteRedirectHandler(base_url),
            urllib.request.HTTPSHandler(context=ssl_context),
        )

    def request_ids_since(self, start_index):
        """Return evidence request ids recorded after `start_index`."""
        return [entry["id"] for entry in self.trace[start_index:]]

    def statistics(self):
        """Return aggregate request statistics for the scan result."""
        return {
            "requests_total": len(self.trace),
            "network_requests": self.requests_made,
            "request_errors": sum(1 for item in self.trace if item["error"]),
            "bytes_received": sum(item["bytes_read"] for item in self.trace),
            "truncated_responses": sum(
                1 for item in self.trace if item["truncated"]
            ),
        }

    def fetch(self, url, method="GET", data=None, content_type=None):
        """Download one URL and record a body hash plus request metadata."""
        request_id = "REQ-" + str(len(self.trace) + 1).zfill(4)
        timestamp = utc_now_text()

        if self.requests_made >= self.max_requests:
            error_text = (
                "request limit reached (" + str(self.max_requests) + ")"
            )
            return self._record_response(
                request_id=request_id,
                timestamp=timestamp,
                method=method,
                url=url,
                status=0,
                body_bytes=b"",
                final_url=url,
                headers={},
                error=error_text,
                truncated=False,
                duration_ms=0,
            )

        wait_seconds = self.delay - (time.monotonic() - self.last_request_started)
        if self.last_request_started and wait_seconds > 0:
            time.sleep(wait_seconds)

        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Connection": "close",
        }
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(
            url,
            data=data,
            headers=headers,
            method=method,
        )

        self.requests_made += 1
        self.last_request_started = time.monotonic()
        started = time.monotonic()

        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body_bytes, truncated = read_limited(
                    response,
                    self.max_response_bytes,
                )
                return self._record_response(
                    request_id=request_id,
                    timestamp=timestamp,
                    method=method,
                    url=url,
                    status=response.status,
                    body_bytes=body_bytes,
                    final_url=response.geturl(),
                    headers=lower_case_headers(response.headers),
                    error="",
                    truncated=truncated,
                    duration_ms=round((time.monotonic() - started) * 1000),
                )

        except urllib.error.HTTPError as error:
            try:
                body_bytes, truncated = read_limited(
                    error,
                    self.max_response_bytes,
                )
            except OSError:
                body_bytes = b""
                truncated = False
            return self._record_response(
                request_id=request_id,
                timestamp=timestamp,
                method=method,
                url=url,
                status=error.code,
                body_bytes=body_bytes,
                final_url=error.geturl(),
                headers=lower_case_headers(error.headers or {}),
                error="",
                truncated=truncated,
                duration_ms=round((time.monotonic() - started) * 1000),
            )

        # This is the network boundary. Unexpected transport/library failures
        # become evidence errors instead of terminating the whole assessment.
        except Exception as error:  # pylint: disable=broad-except
            return self._record_response(
                request_id=request_id,
                timestamp=timestamp,
                method=method,
                url=url,
                status=0,
                body_bytes=b"",
                final_url=url,
                headers={},
                error=str(error),
                truncated=False,
                duration_ms=round((time.monotonic() - started) * 1000),
            )

    def _record_response(
        self,
        request_id,
        timestamp,
        method,
        url,
        status,
        body_bytes,
        final_url,
        headers,
        error,
        truncated,
        duration_ms,
    ):
        """Add one request to the trace and return the check-friendly response."""
        body_hash = hashlib.sha256(body_bytes).hexdigest() if body_bytes else ""
        content_type = headers.get("content-type", "").split(";")[0].strip()
        trace_entry = {
            "id": request_id,
            "timestamp": timestamp,
            "method": method,
            "url": url,
            "status": int(status),
            "final_url": final_url,
            "duration_ms": int(duration_ms),
            "bytes_read": len(body_bytes),
            "truncated": bool(truncated),
            "content_type": content_type,
            "sha256": body_hash,
            "error": error or "",
        }
        self.trace.append(trace_entry)
        return {
            "request_id": request_id,
            "status": int(status),
            "body": body_bytes.decode("utf-8", errors="replace"),
            "byte_length": len(body_bytes),
            "truncated": bool(truncated),
            "final_url": final_url,
            "headers": headers,
            "error": error or None,
        }


def fetch(url, method="GET", data=None, content_type=None, timeout=10, verify_tls=True):
    """Compatibility wrapper for downloading one URL.

    Arguments you will usually care about:
      url           - the address to fetch, e.g. "http://site.tld/wp-login.php"
      method        - "GET" (just read) or "POST" (send data)
      data          - bytes to send when method is "POST"
      timeout       - how many seconds to wait before giving up
      verify_tls    - set to False to ignore HTTPS certificate errors
    """
    parts = urlsplit(url)
    base_url = parts.scheme + "://" + parts.netloc
    client = HttpClient(
        base_url,
        timeout=timeout,
        verify_tls=verify_tls,
        delay=0,
        max_requests=1,
    )
    return client.fetch(url, method=method, data=data, content_type=content_type)


def lower_case_headers(headers):
    """Turn response headers into a simple dict with lower-cased keys.

    We lower-case the keys so we can always look them up the same way,
    for example: response["headers"]["server"].
    """
    result = {}
    for key, value in headers.items():
        result[key.lower()] = value
    return result
