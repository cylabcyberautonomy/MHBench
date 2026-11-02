#!/usr/bin/env python3
"""Legitimate origin portal: serve the login form and validate the synthetic login."""
import json
import syslog
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

CONFIG_PATH = "/etc/mhbench/portal.json"

with open(CONFIG_PATH, encoding="utf-8") as handle:
    CONFIG = json.load(handle)

FORM = """<!doctype html>
<html><head><title>Employee Portal</title></head>
<body><h1>Employee Portal</h1>
<p>Authorized staff sign in to reach the data service.</p>
<form action="/login" method="post">
<input name="username" autocomplete="username">
<input name="password" type="password" autocomplete="current-password">
<button type="submit">Sign in</button>
</form></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        syslog.syslog(syslog.LOG_INFO, "mhbench-portal " + (fmt % args))

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        for name, value in {"Content-Type": "text/html; charset=utf-8", **(headers or {})}.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, b"ORIGIN\n", {"Content-Type": "text/plain"})
        elif self.path == "/":
            self._send(200, FORM.encode())
        elif self.path == "/dashboard":
            self._send(200, b"ok\n", {"Content-Type": "text/plain"})
        else:
            self._send(404, b"not found\n")

    def do_POST(self):
        if self.path != "/login":
            self._send(404, b"not found\n")
            return
        length = int(self.headers.get("Content-Length", "0"))
        fields = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        user = (fields.get("username") or [""])[0]
        password = (fields.get("password") or [""])[0]
        if user == CONFIG["username"] and password == CONFIG["password"]:
            syslog.syslog(syslog.LOG_INFO,
                          f"mhbench-portal login ok user={user} src={self.client_address[0]}")
            self._send(302, b"", {"Location": "/dashboard", "Set-Cookie": "session=ok; Path=/"})
        else:
            syslog.syslog(syslog.LOG_WARNING,
                          f"mhbench-portal login failed user={user} src={self.client_address[0]}")
            self._send(403, b"login failed\n")


if __name__ == "__main__":
    syslog.openlog("mhbench-portal")
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
