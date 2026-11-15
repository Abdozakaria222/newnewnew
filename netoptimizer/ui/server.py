"""Local web UI server (127.0.0.1 only).

Security: binds to loopback only; every API call must carry the per-launch
random token (prevents other websites from driving the API via the browser),
and the Host header must be the loopback address (prevents DNS rebinding).
"""
from __future__ import annotations

import json
import logging
import mimetypes
import os
import re
import secrets
import socket
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from ..core.apply import ApplyError
from ..core.providers import ProviderError

log = logging.getLogger("netopt.server")
STATIC = os.path.join(os.path.dirname(__file__), "static")


def make_handler(app, token: str, port_ref: dict):
    class H(BaseHTTPRequestHandler):
        server_version = "NetworkOptimizer"

        def log_message(self, fmt, *args):
            log.debug("%s - %s", self.address_string(), fmt % args)

        # ---------------------------------------------------- helpers
        def _send(self, code: int, body, ctype="application/json; charset=utf-8", extra=None):
            data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").lower()
            return host in (f"127.0.0.1:{port_ref['port']}", f"localhost:{port_ref['port']}")

        def _auth(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-Token", ""), token)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2_000_000:
                raise ValueError("request too large")
            raw = self.rfile.read(n) if n else b"{}"
            return json.loads(raw.decode("utf-8") or "{}")

        def _job(self, job):
            self._send(200, {"job": job.to_dict()})

        # ---------------------------------------------------- routing
        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_DELETE(self):
            self._dispatch("DELETE")

        def _dispatch(self, method):
            if not self._host_ok():
                return self._send(403, {"error": "bad host"})
            url = urlparse(self.path)
            path = url.path
            if method == "GET" and not path.startswith("/api/"):
                return self._static(path)
            if not self._auth():
                # downloads may use ?t= query because <a href> cannot set headers
                q = parse_qs(url.query)
                if not (method == "GET" and secrets.compare_digest((q.get("t") or [""])[0], token)):
                    return self._send(401, {"error": "unauthorized"})
            try:
                self._api(method, path, parse_qs(url.query))
            except (ApplyError, ProviderError, ValueError, KeyError, RuntimeError) as e:
                self._send(400, {"error": str(e)})
            except Exception as e:
                log.error("API error %s %s\n%s", method, path, traceback.format_exc())
                self._send(500, {"error": f"internal error: {e}"})

        def _static(self, path):
            if path in ("", "/"):
                path = "/index.html"
            rel = os.path.normpath(path.lstrip("/"))
            if rel.startswith("..") or os.path.isabs(rel):
                return self._send(404, {"error": "not found"})
            full = os.path.join(STATIC, rel)
            if not os.path.isfile(full):
                return self._send(404, {"error": "not found"})
            ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            with open(full, "rb") as f:
                self._send(200, f.read(), ctype)

        def _api(self, method, path, q):
            a = app
            p = path[len("/api"):]
            if method == "GET" and p == "/state":
                return self._send(200, a.state())
            if method == "POST" and p == "/refresh":
                a.refresh()
                return self._send(200, a.state())
            if method == "POST" and p in ("/dns/start", "/mtu/start", "/workflow/start"):
                fams = self._body().get("families")
                fn = {"/dns/start": a.start_dns, "/mtu/start": a.start_mtu,
                      "/workflow/start": a.start_workflow}[p]
                return self._job(fn(fams))
            m = re.fullmatch(r"/job/([0-9a-f]+)(/cancel)?", p)
            if m:
                job = a.jobs.get(m.group(1))
                if not job:
                    return self._send(404, {"error": "no such job"})
                if m.group(2) and method == "POST":
                    a.jobs.cancel(job.id)
                return self._job(job)
            if method == "GET" and p == "/results":
                return self._send(200, a.results)
            if method == "POST" and p == "/apply":
                return self._send(200, a.apply(self._body()))
            if method == "POST" and p == "/restore":
                return self._send(200, a.restore(self._body()))
            if method == "POST" and p == "/restore/profile":
                return self._send(200, a.restore_previous_profile())
            if method == "GET" and p == "/backups":
                return self._send(200, {"backups": a.backups.list(), "folder": a.backups.folder})
            m = re.fullmatch(r"/backups/([A-Za-z0-9_.-]+\.json)", p)
            if m and method == "GET":
                b = a.backups.get(m.group(1))
                if not b:
                    return self._send(404, {"error": "not found"})
                return self._send(200, json.dumps(b, ensure_ascii=False, indent=2).encode("utf-8"),
                                  "application/json; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="{m.group(1)}"'})
            if p == "/settings":
                if method == "POST":
                    a.settings.update(self._body())
                return self._send(200, a.settings.values)
            if method == "POST" and p == "/settings/reset":
                return self._send(200, a.settings.reset())
            if p == "/providers":
                if method == "POST":
                    a.providers.add_custom(self._body())
                sysdns = ((a.primary or {}).get("dns4") or []) + ((a.primary or {}).get("dns6") or [])
                from dataclasses import asdict
                return self._send(200, {"providers": [asdict(x) for x in a.providers.all(sysdns)]})
            m = re.fullmatch(r"/providers/([a-z0-9_.-]+)", p)
            if m and method == "DELETE":
                return self._send(200, {"removed": a.providers.remove_custom(m.group(1))})
            if method == "GET" and p == "/providers/export":
                tmp = os.path.join(a.backups.folder, "..", "dns_providers_export.json")
                a.providers.export(tmp)
                with open(tmp, "rb") as f:
                    data = f.read()
                return self._send(200, data, "application/json; charset=utf-8",
                                  {"Content-Disposition": 'attachment; filename="dns_providers.json"'})
            if method == "POST" and p == "/providers/import":
                return self._send(200, a.providers.import_data(self._body()))
            if method == "GET" and p == "/profiles":
                return self._send(200, {"profiles": a.profiles.all(),
                                        "current": a.profile["key"] if a.profile else None})
            m = re.fullmatch(r"/profiles/([0-9a-f]+)(/rename)?", p)
            if m:
                if method == "POST" and m.group(2):
                    return self._send(200, {"ok": a.profiles.rename(m.group(1), self._body().get("label", ""))})
                if method == "DELETE":
                    return self._send(200, {"ok": a.profiles.delete(m.group(1))})
            m = re.fullmatch(r"/compare/(before|after)", p)
            if m and method == "POST":
                return self._job(a.start_compare(m.group(1)))
            if method == "GET" and p == "/compare":
                return self._send(200, a.compare_state.get("result") or {})
            if method == "GET" and p == "/events":
                since = int((q.get("since") or ["0"])[0])
                return self._send(200, {"events": a.monitor.since(since)})
            m = re.fullmatch(r"/tool/([a-z_]+)", p)
            if m and method == "POST":
                return self._job(a.start_tool(m.group(1)))
            if method == "GET" and p == "/report":
                data = json.dumps(a.report(), ensure_ascii=False, indent=2, default=str).encode("utf-8")
                fn = time.strftime("netopt-diagnostics-%Y%m%d-%H%M%S.json")
                return self._send(200, data, "application/json; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="{fn}"'})
            if method == "GET" and p == "/log":
                try:
                    with open(a.log_file, "rb") as f:
                        f.seek(0, 2)
                        f.seek(max(0, f.tell() - 60000))
                        return self._send(200, f.read(), "text/plain; charset=utf-8")
                except OSError:
                    return self._send(200, b"", "text/plain; charset=utf-8")
            self._send(404, {"error": "unknown endpoint"})

    return H


def free_port(preferred: int = 8765) -> int:
    for port in [preferred] + list(range(preferred + 1, preferred + 20)):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve(app, port: int | None = None, open_browser: bool = True, token: str | None = None):
    token = token or secrets.token_urlsafe(24)
    port = port or free_port()
    port_ref = {"port": port}
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app, token, port_ref))
    httpd.daemon_threads = True
    url = f"http://127.0.0.1:{port}/#t={token}"
    log.info("NetworkOptimizer UI: %s", url)
    print(f"\n  NetworkOptimizer is running.\n  Open: {url}\n  (Close this window to exit.)\n")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    return httpd, url
