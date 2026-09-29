#!/usr/bin/env python3
"""Transparent telemetry fan-out relay — the fixed bake target on the management host.

Sensors ship to ONE constant address (this host:port, e.g. 10.0.1.10:9200); the relay forwards each
request BYTE-FOR-BYTE to every configured downstream. Redirection lives here, not on the victims:
change the downstreams file and the stream re-routes, with no victim-side change. Fan-out = several
downstreams for one source; multi-stream routing = one relay per source port.

- stdlib only (runs on the plain management host image).
- Downstreams are read fresh per request from a JSON file: {"dests": ["http://host:port/path", ...]}.
  The arena rewrites that file (program_telemetry) to (re)point the stream; no restart needed.
- The relay does NOT parse/reshape the payload — it forwards the raw request body + method + path to
  each dest and returns 200 to the sensor as long as at least one dest accepted (best-effort fan-out;
  a slow/dead dest never blocks the sensor).

Usage: telemetry_relay.py --port 9200 --dests /etc/telemetry_relay/dests.json
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_DESTS_PATH = "/etc/telemetry_relay/dests.json"


def _load_dests() -> list[str]:
    try:
        with open(_DESTS_PATH) as f:
            return list(json.load(f).get("dests", []))
    except Exception:
        return []


class _Relay(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _forward(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        dests = _load_dests()
        ok = 0
        for dest in dests:
            # Preserve the sensor's path onto each dest that ends in "/".
            url = dest.rstrip("/") + self.path if dest.endswith("/") else dest
            try:
                req = urllib.request.Request(url, data=body, method=self.command,
                                             headers={"Content-Type": self.headers.get("Content-Type", "application/json")})
                with urllib.request.urlopen(req, timeout=5) as r:
                    r.read()
                ok += 1
            except Exception:
                pass  # a dead/slow downstream must never block the sensor
        # Ack the sensor regardless (fire-and-forget upstream); 200 if any dest took it, 202 if none yet.
        self.send_response(200 if ok else 202)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = _forward
    do_PUT = _forward

    def do_GET(self):  # health check
        self.send_response(200)
        payload = json.dumps({"relay": "up", "dests": _load_dests()}).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):  # quiet
        pass


def main():
    global _DESTS_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9200)
    ap.add_argument("--dests", default=_DESTS_PATH)
    args = ap.parse_args()
    _DESTS_PATH = args.dests
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), _Relay)
    print(f"telemetry_relay listening on :{args.port}, dests <- {_DESTS_PATH}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
