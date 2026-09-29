# telemetry_relay.py — the fixed telemetry bake target (management host)

Transparent HTTP fan-out relay. Sensors ship to ONE constant address on the
management host (`<mgmt.host_ip>:9200`, e.g. `10.0.1.10:9200`); the relay
forwards each request **byte-for-byte** (method + path + raw body) to every
downstream listed in `/etc/telemetry_relay/dests.json`. Redirection and
fan-out live here, not on the victims — rewrite the dests file and the stream
re-routes with no victim-side change.

## Live-validated (2026-09-29)
Deployed `chain_2hosts_instrumented` (project `relaylive1`), ran the relay on
the mgmt host `10.0.1.10:9200` with `dests=[http://10.81.1.20:9200/]`,
repointed host0's falcosidekick at the relay (index `falco-relaylive1`),
triggered a falco `/etc/shadow` alert, and confirmed 3 docs arrived at the
harness ES via the relay — the `Sensitive file opened for reading` events,
intact. Proves: constant bake target, raw ES-bulk forwarding with the index
path preserved, redirection owned by the relay.

## Provisioning wiring (still to bake — see ARENA_PLUGIN_REQUIREMENTS.md item 3)
1. Ship this script to the mgmt host + a `telemetry_relay.service` systemd unit
   (`ExecStart=/usr/bin/python3 telemetry_relay.py --port 9200`), started at
   configure time with a per-deploy `dests.json`.
2. Open `management_sg` ingress tcp/9200 from every victim subnet.
3. Bake sensors (`install_falco_nostart` / `install_filebeat_nostart`
   `es_address`) to the relay `http://<mgmt.host_ip>:9200` instead of a
   hardcoded ES — this is the `telemetry_ingest()` constant in the harness.

Validated by hand in this pass; the automatic wiring is the remaining code.
