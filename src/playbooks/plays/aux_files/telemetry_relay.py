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
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HOP_BY_HOP = {"content-length", "transfer-encoding", "connection", "keep-alive"}

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
        """Transparent proxy: forward the request (method + path + body) to every dest, and return the
        FIRST dest's real response (status + headers + body) to the client. Extra dests are fan-out
        (fire-and-forget). Returning the real response — including headers like X-Elastic-Product — is
        what lets a proper ES client (sf-processor's go-elasticsearch, which does a product-check GET /)
        work through the relay, not just a header-agnostic shipper like falcosidekick."""
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        data = body if self.command in ("POST", "PUT") else None
        dests = _load_dests()
        primary = None  # (status, body, headers) from the first dest — proxied back to the client
        for i, dest in enumerate(dests):
            # Preserve the sensor's path onto each dest that ends in "/".
            url = dest.rstrip("/") + self.path if dest.endswith("/") else dest
            try:
                req = urllib.request.Request(url, data=data, method=self.command,
                                             headers={"Content-Type": self.headers.get("Content-Type", "application/json")})
                with urllib.request.urlopen(req, timeout=15) as r:
                    rbody = r.read()
                    if i == 0:
                        primary = (r.status, rbody, r.headers)
            except urllib.error.HTTPError as e:
                # a 4xx/5xx from the dest is still a real response (e.g. ES rejecting a bulk) — proxy it.
                if i == 0:
                    primary = (e.code, e.read(), e.headers)
            except Exception:
                if i == 0:
                    primary = None  # dead/unreachable primary -> 502 below (extra dests never block)
        if primary is not None:
            status, rbody, rheaders = primary
            self.send_response(status)
            for k, v in rheaders.items():
                if k.lower() not in _HOP_BY_HOP:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(rbody)))
            self.end_headers()
            self.wfile.write(rbody)
        else:
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()

    do_POST = _forward
    do_PUT = _forward
    do_HEAD = _forward
    do_DELETE = _forward

    def do_GET(self):
        # /__relay__ is the relay's own health check; everything else is proxied to the dest (so ES
        # version/product-check GETs pass through with the real response).
        if self.path == "/__relay__":
            payload = json.dumps({"relay": "up", "dests": _load_dests()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self._forward()

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
