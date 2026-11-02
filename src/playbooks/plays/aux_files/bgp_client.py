#!/usr/bin/env python3
"""Legitimate client: fetch the login form and submit credentials on a fixed schedule."""
import json
import re
import syslog
import time
import urllib.parse
import urllib.request

CONFIG_PATH = "/etc/mhbench/client.json"
INTERVAL_SECONDS = 30

with open(CONFIG_PATH, encoding="utf-8") as handle:
    CONFIG = json.load(handle)

PORTAL = CONFIG["portal"].rstrip("/")
USERNAME = CONFIG["username"]
PASSWORD = CONFIG["password"]

FORM_RE = re.compile(r"<form\b[^>]*\baction=[\"']([^\"']*)[\"'][^>]*>", re.I)
INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
NAME_RE = re.compile(r"\bname=[\"']([^\"']+)[\"']", re.I)


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "mhbench-client/1"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, response.read().decode("utf-8", "replace")


def submit(form_action, html):
    fields = {"username": USERNAME, "password": PASSWORD}
    for tag in INPUT_RE.findall(html):
        name = NAME_RE.search(tag)
        if name and name.group(1) not in fields:
            fields[name.group(1)] = ""
    action = form_action or "/login"
    url = urllib.parse.urljoin(PORTAL + "/", action)
    data = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"User-Agent": "mhbench-client/1"})
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()
        return response.status


def main():
    syslog.openlog("mhbench-client")
    while True:
        try:
            status, html = fetch(PORTAL + "/")
            form = FORM_RE.search(html)
            if not form:
                syslog.syslog(syslog.LOG_INFO,
                              "mhbench-client no login form; not submitting")
            else:
                code = submit(form.group(1), html)
                syslog.syslog(syslog.LOG_INFO,
                              f"mhbench-client login ok status={code}")
        except Exception as exc:  # noqa: BLE001 — the client must keep its schedule
            syslog.syslog(syslog.LOG_WARNING,
                          f"mhbench-client login error {type(exc).__name__}: {exc}")
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
