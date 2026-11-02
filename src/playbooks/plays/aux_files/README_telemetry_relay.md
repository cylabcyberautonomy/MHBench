# Telemetry relay on the management host

Sensors send telemetry to `management.host_ip:9200`. The relay reads `/etc/telemetry_relay/dests.json` for each request and forwards to its `dests` list. A destination ending in `/` preserves the incoming request path; otherwise the destination URL is used as written. POST/PUT bodies are forwarded without parsing.

The client receives the first destination's HTTP status, response headers, and body, or HTTP 502 if that destination is unreachable. Additional destinations are attempted sequentially with a 15-second timeout each; they can delay the response.

## Configuration

`AnsibleRunner` installs and starts the relay through `setup_telemetry_relay.yml` during configuration when a management host is present. Relay setup failures are logged without failing the whole deployment. The playbook preserves an existing destinations file. `MHBENCH_RELAY_ES_ADDRESS` supplies the initial downstream when that file is first created.

Management security-group rules permit victim telemetry on TCP/9200. Arena's `program_ingress()` uses MHBench's `request-ingress --telemetry PORT` to direct the relay to the defender's Elasticsearch. Changing the destinations file redirects subsequent requests without restarting the relay or reconfiguring sensors.

## Live-validated (2026-09-29)
Deployed `chain_2hosts_instrumented` (project `relaylive1`), ran the relay on
the mgmt host `10.0.1.10:9200` with `dests=[http://10.81.1.20:9200/]`,
repointed host0's falcosidekick at the relay (index `falco-relaylive1`),
triggered a falco `/etc/shadow` alert, and confirmed 3 docs arrived at the
harness ES via the relay — the `Sensitive file opened for reading` events,
intact. Proves: constant bake target, raw ES-bulk forwarding with the index
path preserved, redirection owned by the relay.
