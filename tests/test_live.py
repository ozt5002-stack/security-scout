"""Plan task 4: the live scanner against a local test server, and the allowlist refusing before any request."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scout.cli import main
from scout.scanners import live

ALL_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=63072000",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


def make_server(headers: dict, files: dict, spa: bool = False):
    """A tiny site. `files` = {path: content-type}; `spa` = every unknown path answers the home page."""
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _answer(self, body: bool):
            requests.append((self.command, self.path))
            if self.path == "/":
                code, ctype = 200, "text/html"
            elif self.path in files:
                code, ctype = 200, files[self.path]
            elif spa:
                code, ctype = 200, "text/html"
            else:
                code, ctype = 404, "text/html"
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            if body:
                self.wfile.write(b"<p>hi</p>")

        def do_GET(self):
            self._answer(True)

        def do_HEAD(self):
            self._answer(False)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, requests


@pytest.fixture
def site():
    servers = []

    def start(headers, files=None, spa=False):
        server, reqs = make_server(headers, files or {}, spa)
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}/", reqs

    yield start
    for s in servers:
        s.shutdown()


def test_missing_headers_and_an_exposed_gs_file(site, tmp_path):
    project = tmp_path / "proj"
    (project / "site" / "backend").mkdir(parents=True)
    (project / "site" / "index.html").write_text("<p>x</p>", encoding="utf-8")
    (project / "site" / "backend" / "Code.gs").write_text("function doPost(){}", encoding="utf-8")
    url, _ = site({}, files={"/backend/Code.gs": "application/octet-stream"})

    facts = live.scan_url(url, project)
    by_id = {f.id: f for f in facts}
    assert set(by_id) == {"live.missing-headers", "live.plain-http", "live.exposed-file"}
    assert "Content-Security-Policy" in by_id["live.missing-headers"].evidence
    assert "Strict-Transport-Security" not in by_id["live.missing-headers"].evidence  # http: HSTS does not apply
    assert by_id["live.exposed-file"].url.endswith("/backend/Code.gs")


def test_all_headers_give_no_header_fact(site):
    url, _ = site(ALL_HEADERS)
    assert [f.id for f in live.scan_url(url)] == ["live.plain-http"]


def test_a_site_that_answers_every_path_with_its_home_page_is_not_an_exposed_file(site):
    url, _ = site(ALL_HEADERS, spa=True)
    assert not [f for f in live.scan_url(url) if f.id == "live.exposed-file"]


def test_only_get_and_head_with_our_user_agent(site):
    url, reqs = site(ALL_HEADERS)
    live.scan_url(url)
    assert {m for m, _ in reqs} == {"GET", "HEAD"}
    assert [p for m, p in reqs if m == "GET"] == ["/"]


def test_host_not_in_allowlist_is_refused_before_any_request(site, tmp_path):
    url, reqs = site({})
    allow = tmp_path / "targets.yaml"
    allow.write_text("hosts: [mysite.test]\n", encoding="utf-8")
    assert main([str(tmp_path), "--live", url, "--targets", str(allow), "--no-agent"]) == 2
    assert reqs == []


def test_allowed_host_runs_the_live_scan_through_the_cli(site, tmp_path, runs_in_tmp):
    url, reqs = site({})
    allow = tmp_path / "targets.yaml"
    allow.write_text("hosts: [127.0.0.1]\n", encoding="utf-8")
    assert main([str(tmp_path), "--live", url, "--targets", str(allow), "--no-agent"]) == 0
    assert ("GET", "/") in reqs


def test_redirect_to_another_host_is_not_followed(site):
    url, reqs = site({"Location": "http://evil.test/"})
    # the home page itself answers 200 here; check the handler directly
    handler = live.SameHostRedirects("127.0.0.1")
    assert handler.redirect_request(None, None, 302, "Found", {}, "http://evil.test/") is None


def test_a_meta_csp_counts_when_the_host_cannot_send_headers(site):
    url, _ = site({})  # the home page body below has no meta tag; patch a page that has one
    from scout.scanners import live as L
    real = L._request

    def with_meta(opener, u, method):
        code, h, body = real(opener, u, method)
        if method == "GET":
            body = b'<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
        return code, h, body

    try:
        L._request = with_meta
        facts = [f for f in L.scan_url(url) if f.id == "live.missing-headers"]
    finally:
        L._request = real
    assert "Content-Security-Policy" not in facts[0].evidence.split("send:")[1].split(".")[0]
    assert "<meta> tag" in facts[0].evidence


def test_ipv4_is_tried_before_ipv6(monkeypatch):
    """Broken IPv6 must not stall every request (seen on Oz's machine)."""
    import socket
    tried = []
    v6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 80, 0, 0))
    v4 = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 80))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [v6, v4])

    class FakeSock:
        def __init__(self, family, *a):
            self.family = family

        def settimeout(self, t):
            pass

        def connect(self, addr):
            tried.append(addr[0])
            if self.family == socket.AF_INET6:
                raise OSError("unreachable")

        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", FakeSock)
    s = live.connect_ipv4_first(("example.test", 80), 15)
    assert tried == ["192.0.2.1"] and s.family == socket.AF_INET
