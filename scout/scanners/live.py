"""Safe checks on a live site the user owns (OWASP A02; architecture D5).

Ordinary requests only: one GET of the home page (its security headers), and a HEAD for a short list of paths that
should never answer (`/.env`, `/.git/config`, ...) plus every non-web file the `publish` scanner found, mapped to its
URL. No payloads, no guessing, a timeout, a clear User-Agent, and redirects are followed only on the same host.
The caller (the CLI) has already checked the host against the allowlist before this module sends anything.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from scout import __version__
from scout.facts import Fact
from scout.scanners import Context
from scout.scanners.files import walk
from scout.scanners.publish import CSP_META, RISKY, SKIP, publish_folders

NAME = "live"
USER_AGENT = f"security-scout/{__version__} (owner-authorized security check)"
TIMEOUT = 15
ALWAYS_CHECK = ["/.env", "/.git/config", "/.git/HEAD", "/.DS_Store", "/backup.zip", "/.env.local"]

# The six headers from lesson 12 (HSTS only matters over https).
HEADERS = {
    "content-security-policy": "Content-Security-Policy (which scripts, styles and frames may load)",
    "strict-transport-security": "Strict-Transport-Security (always use HTTPS)",
    "x-frame-options": "X-Frame-Options (or CSP frame-ancestors: no framing by other sites)",
    "x-content-type-options": "X-Content-Type-Options: nosniff",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy (camera, microphone, location)",
}


class SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only on the same host: a redirect must never carry us to a site that is not allowlisted."""

    def __init__(self, host: str):
        self.host = host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).hostname != self.host:
            return None  # stop here; the 3xx response is what we report on
        return super().redirect_request(req, fp, code, msg, headers, newurl)


CONNECT_TIMEOUT = 5


def connect_ipv4_first(address, timeout=None, source_address=None, *args, **kwargs):
    """Like socket.create_connection, but tries IPv4 addresses first and gives each address at most CONNECT_TIMEOUT
    seconds. On a network with broken IPv6 the standard order waits the full timeout on every IPv6 address first
    (found on Oz's machine: minutes per check), while curl and browsers fall back at once."""
    host, port = address
    infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
    last_error: OSError | None = None
    for family, kind, proto, _name, sockaddr in infos:
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(min(timeout or CONNECT_TIMEOUT, CONNECT_TIMEOUT))
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            sock.settimeout(timeout)
            return sock
        except OSError as e:
            last_error = e
            sock.close()
    raise last_error or OSError(f"could not connect to {host}:{port}")


class _HTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = connect_ipv4_first((self.host, self.port), self.timeout, self.source_address)


class _HTTPS(http.client.HTTPSConnection):
    def connect(self):  # no proxy tunnel (ProxyHandler({})), so: connect, then TLS with hostname checking
        sock = connect_ipv4_first((self.host, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_HTTP, req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_HTTPS, req, context=ssl.create_default_context())


def _opener(host: str):
    # ProxyHandler({}): talk to the site directly, as the allowlist check assumed.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _HTTPHandler(), _HTTPSHandler(),
                                       SameHostRedirects(host))


def _request(opener, url: str, method: str):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(200_000) if method == "GET" else b""
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, b""


def _missing_headers(headers: dict[str, str], https: bool) -> list[str]:
    missing = []
    for name in HEADERS:
        if name == "strict-transport-security" and not https:
            continue
        if name == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", ""):
            continue
        if name not in headers:
            missing.append(name)
    if headers.get("x-content-type-options", "").strip().lower() not in ("", "nosniff"):
        missing.append("x-content-type-options")
    return missing


def candidate_paths(project: Path | None) -> dict[str, str]:
    """{path: severity if it answers}: ALWAYS_CHECK (high) + every risky file inside the project's publish folders,
    mapped to its URL, with the publish scanner's severity for that kind of file."""
    paths = dict.fromkeys(ALWAYS_CHECK, "high")
    if project is not None:
        project = project.resolve()
        for folder in publish_folders(project):
            for p in walk(folder, SKIP):
                suffix = ".env" if p.name.startswith(".env") else p.suffix.lower()
                if suffix in RISKY:
                    paths.setdefault("/" + p.relative_to(folder).as_posix(), RISKY[suffix])
    return paths


def scan_url(url: str, project: Path | None = None) -> list[Fact]:
    parts = urlsplit(url)
    host = parts.hostname or ""
    base = f"{parts.scheme}://{parts.netloc}/"
    opener = _opener(host)
    facts: list[Fact] = []

    try:
        status, headers, home = _request(opener, base, "GET")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return [Fact(NAME, "live.unreachable", "A02", "info", f"not checked: {base} did not answer ({e})", url=base)]

    missing = _missing_headers(headers, parts.scheme == "https")
    note = ""
    if "content-security-policy" in missing and CSP_META.search(home.decode("utf-8", errors="replace")):
        missing.remove("content-security-policy")  # hosts like GitHub Pages cannot send headers; a meta CSP counts
        note = " The page sets its CSP in a <meta> tag (it cannot block framing: that needs a header)."
    if missing:
        severity = "medium" if {"content-security-policy", "x-frame-options"} & set(missing) else "low"
        facts.append(Fact(NAME, "live.missing-headers", "A02", severity,
                          f"{base} (HTTP {status}) does not send: "
                          f"{', '.join(HEADERS[m].split(' (')[0] for m in missing)}.{note}",
                          url=base))
    if parts.scheme == "http":
        facts.append(Fact(NAME, "live.plain-http", "A04", "medium", f"{base} was checked over plain HTTP", url=base))

    for path, severity in candidate_paths(project).items():
        target = urljoin(base, path.lstrip("/"))
        try:
            code, h, _ = _request(opener, target, "HEAD")
        except (urllib.error.URLError, TimeoutError, OSError):
            continue
        # Many static hosts answer every path with the home page (200, text/html); that is not an exposed file.
        if code == 200 and not h.get("content-type", "").startswith("text/html"):
            facts.append(Fact(NAME, "live.exposed-file", "A02", severity,
                              f"{target} answers 200 ({h.get('content-type', 'no content-type')}): anyone can download it",
                              url=target))
    return facts


def scan(project: Path, ctx: Context) -> list[Fact]:
    return scan_url(ctx.live_url, project) if ctx.live_url else []
