#!/usr/bin/env python3
"""Provision, verify, and tear down MHBench's fixed three-AS BGP attack scenario."""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from config.config import Config
from src.compilation.offline_registry_service import OfflineRegistryService
from src.deployment.backends.openstack_backend import OpenStackBackend
from src.deployment.online_registry_service import OnlineRegistryService
from src.deployment.orchestrator import DeploymentOrchestrator
from src.deployment.routing import router_peers
from src.deployment.spec_parsers import JsonSpecParser
from src.playbooks.playbook_registry_service import PlaybookRegistryService

P, H, C = "198.19.0.0/23", "198.19.0.0/24", "198.18.0.0/24"
TARGET, SOURCE = "198.19.0.10", "198.18.0.10"
HOSTS = {
    "origin-router": ["10.200.1.10/24", "10.250.0.1/30", "198.19.0.1/23"],
    "transit-router": ["10.200.2.10/24", "10.250.0.2/30", "10.250.0.5/30", "198.18.0.1/24"],
    "attacker-router": ["10.200.3.10/24", "10.250.0.6/30", "10.250.0.9/30"],
    "client": ["10.200.2.20/24", "198.18.0.10/24"],
    "server": ["10.200.1.20/24", "198.19.0.10/23"],
    "vault": ["10.200.1.30/24", "198.19.1.20/23"],
    "kali": ["10.200.3.20/24", "10.250.0.10/30"],
}
ASNS = {"origin-router": 65001, "transit-router": 65002, "attacker-router": 65003}
PEERS = {"origin-router": ["10.250.0.2"], "transit-router": ["10.250.0.1", "10.250.0.6"],
         "attacker-router": ["10.250.0.5"]}
DATA = {"origin_transit": "10.250.0.0/30", "transit_attacker": "10.250.0.4/30",
        "attacker_lan": "10.250.0.8/30", "origin_lan": P, "client_lan": C}
GATEWAYS = {"server": "198.19.0.1", "vault": "198.19.0.1", "client": "198.18.0.1",
            "kali": "10.250.0.9"}
SERVICES = {"server": ("mhbench-portal", "ORIGIN"),
            "vault": ("mhbench-vault", "VAULT"),
            "client": ("mhbench-client", None)}
LOG = logging.getLogger("bgp-three-as")

# The temporary attacker-side responder: the runner's equivalent of the Kali
# login-impersonation service, bound to the hijacked address.
PROBE = """
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'ATTACKER\\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        pass
HTTPServer(('198.19.0.10', 8080), Handler).serve_forever()
"""

# EOF (including a controller disconnect) or the deadline stops this exact child.
CAPTURE = """
import os,select,signal,subprocess,sys,time
os.environ['LC_ALL']='C'
p=subprocess.Popen(sys.argv[1:],stdin=subprocess.DEVNULL)
try:
    deadline=time.monotonic()+600
    while True:
        readable=select.select([sys.stdin],[],[],0.2)[0]
        if p.poll() is not None:
            raise RuntimeError('tcpdump exited before the stop request')
        if readable:
            break
        if time.monotonic()>=deadline:
            raise TimeoutError('capture deadline expired')
finally:
    if p.poll() is None:
        p.send_signal(signal.SIGINT)
    try:
        rc=p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill();p.wait();raise
sys.exit(rc)
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def unique(items, description):
    require(len(items) == 1, f"Expected one {description}, found {len(items)}")
    return items[0]


def address_devices(rows, expected):
    result = {}
    for address in expected:
        matches = [r["ifname"] for r in rows if any(
            f"{a['local']}/{a['prefixlen']}" == address for a in r.get("addr_info", []))]
        result[address] = unique(matches, "interface for " + address)
    return result


def bgp_path(data, prefix, via, asn, preference):
    paths = [p for p in data.get("paths", []) if p.get("bestpath", {}).get("overall")]
    return (data.get("prefix") == prefix and len(paths) == 1
            and paths[0].get("valid") is True
            and paths[0].get("aspath", {}).get("string") == str(asn)
            and paths[0].get("localpref") == preference
            and any(n.get("ip") == via and n.get("used") is True for n in paths[0].get("nexthops", [])))


def host_routes(routes, rules, control, data, gateway):
    ordinary = [(0, "local"), (32766, "main"), (32767, "default")]
    require([(r.get("priority"), r.get("table")) for r in rules] == ordinary
            and all(r.get("src") == "all" and not (set(r) - {"priority", "table", "src", "protocol"})
                    for r in rules), "Unexpected policy-routing rules")
    defaults = [r for r in routes if r.get("dst") == "default"]
    require(len(defaults) == 1 and defaults[0].get("gateway") == gateway
            and defaults[0].get("dev") == data, "Wrong or competing end-host default gateway")
    for route in routes:
        if route.get("dev") == control:
            prefix = ipaddress.ip_network(route["dst"])
            require(not any(prefix.overlaps(ipaddress.ip_network(p)) for p in DATA.values()),
                    f"Control route covers experimental data: {route}")


def check_guard(forward, chain, nat, control, responses=()):
    require(forward.splitlines() == ["-P FORWARD ACCEPT", "-A FORWARD -j MHBENCH_FORWARD"],
            "Unexpected forwarding rules or guard ordering")
    expected = ["-N MHBENCH_FORWARD", f"-A MHBENCH_FORWARD -i {control} -j DROP",
                f"-A MHBENCH_FORWARD -o {control} -j DROP"]
    for interface, prefix in responses:
        expected += [
            f"-A MHBENCH_FORWARD -s {prefix} -i {interface} -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
            f"-A MHBENCH_FORWARD -s {prefix} -i {interface} -j DROP",
        ]
    require(chain.splitlines() == expected + ["-A MHBENCH_FORWARD -j RETURN"],
            "Control/data/response forwarding guard differs from the fixed experiment")
    require(nat.splitlines() == [f"-P {c} ACCEPT" for c in
                                ["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"]],
            "Unexpected NAT rules")


def drop_counter(text, control):
    rows = [line.split() for line in text.splitlines()]
    matches = [int(r[0]) for r in rows if len(r) >= 9 and r[0].isdigit()
               and r[2] == "DROP" and r[5] == "*" and r[6] == control]
    return unique(matches, "control-facing DROP counter")


def capture_evidence(files, probes):
    text = {role: path.read_text() for role, path in files.items()}
    require(not text["control"].strip(), "TCP/8080 traffic appeared on transit's control interface")
    result = {}
    for stage, probe in probes.items():
        port = probe["port"]
        request = f"{SOURCE}.{port} > {TARGET}.8080:"
        response = f"{TARGET}.8080 > {SOURCE}.{port}:"
        selected = probe["wan"]
        counts = {role: {"request": output.count(request), "reply": output.count(response)}
                  for role, output in text.items()}
        for role in ["client", selected]:
            require(counts[role]["request"] > 0 and counts[role]["reply"] > 0,
                    f"{stage}: missing request/reply capture on {role}")
        unused = "attacker" if selected == "origin" else "origin"
        require(counts[unused] == {"request": 0, "reply": 0},
                f"{stage}: probe appeared on unused {unused} WAN")
        result[stage] = counts
    return result


class Capture:
    def __init__(self, command, output):
        self.output = output
        self.stdout = output.open("wb")
        self.stderr = output.with_suffix(".stderr").open("wb")
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=self.stdout,
                                            stderr=self.stderr)
        except OSError:
            self.stdout.close()
            self.stderr.close()
            raise

    def ready(self):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            require(self.process.poll() is None, f"Capture exited early: {self.output.with_suffix('.stderr')}")
            if "listening on " in self.output.with_suffix(".stderr").read_text():
                return
            time.sleep(0.1)
        raise RuntimeError(f"Capture did not become ready: {self.output}")

    def stop(self):
        early = self.process.poll() is not None
        try:
            self.process.stdin.close()
            rc = self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise RuntimeError(f"Capture SSH did not stop: {self.output}")
        finally:
            self.stdout.close()
            self.stderr.close()
        stderr = self.output.with_suffix(".stderr").read_text()
        require(not early and rc == 0, f"Capture failed: {stderr}")
        require(re.search(r"(?m)^0 packets dropped by kernel$", stderr) is not None,
                f"Capture loss or missing drop statistics: {stderr}")


class Experiment:
    def __init__(self, config, topology, project, output):
        self.config, self.topology, self.project, self.output = config, topology, project, output
        self.backend = OpenStackBackend(config, OnlineRegistryService(config), project)
        self.conn = self.backend.conn
        self.conn.session.timeout = 30
        self.pid = self.conn.current_project_id
        self.orchestrator = DeploymentOrchestrator(
            self.backend, config, OnlineRegistryService(config), PlaybookRegistryService(config), project)
        self.mgmt = None
        self.devices, self.captures, self.probes = {}, {}, {}
        self.fip_ids = set()
        self.initial_fip_ids = None
        self.shutdown = self.announced = self.owned = False
        self.probe_pid = None
        self.probe_started = self.routed = False
        self.report = {"observations": {}, "cleanup_errors": []}
        self.commands = (output / "commands.jsonl").open("w")
        self.server_names = {self.n(name) for name in [*HOSTS, "management_host"]}
        self.network_names = {self.n(s.name) for s in topology.get_all_subnets()} | {self.n("management_network")}
        self.subnet_names = {self.n(s.name + "-subnet") for s in topology.get_all_subnets()} | {self.n("management_subnet")}
        self.sg_names = {self.n(s + "_sg") for s in ["origin_control", "transit_control",
                         "attacker_subnet", "origin_lan", "client_lan", "attacker_lan"]} | {self.n("management_sg")}

    def n(self, name):
        return self.project + "-" + name

    def resources(self):
        servers = list(self.conn.compute.servers(name=self.project + "-", project_id=self.pid))
        networks = [n for n in self.conn.network.networks(project_id=self.pid)
                    if n.name.startswith(self.project + "-")]
        subnets = [s for s in self.conn.network.subnets(project_id=self.pid)
                   if s.name.startswith(self.project + "-")]
        routers = [r for r in self.conn.network.routers(project_id=self.pid)
                   if r.name.startswith(self.project + "-")]
        groups = [s for s in self.conn.network.security_groups(project_id=self.pid)
                  if s.name.startswith(self.project + "-")]
        ports = [p for p in self.conn.network.ports(project_id=self.pid)
                 if p.network_id in {n.id for n in networks} or p.name.startswith(self.project + "-")]
        all_fips = list(self.conn.network.ips(project_id=self.pid))
        if self.initial_fip_ids is None:
            self.initial_fip_ids = {f.id for f in all_fips}
        fips = [f for f in all_fips if f.port_id in {p.id for p in ports} or f.id in self.fip_ids]
        self.fip_ids.update(f.id for f in fips)
        return dict(servers=servers, networks=networks, subnets=subnets, routers=routers,
                    groups=groups, ports=ports, fips=fips)

    def validate_namespace(self, resources):
        expected = dict(servers=self.server_names, networks=self.network_names,
                        subnets=self.subnet_names, routers={self.n("router")}, groups=self.sg_names)
        for kind, names in expected.items():
            require(all(r.name in names for r in resources[kind]),
                    f"Unexpected or ambiguous {kind} in project namespace")
            require(len({r.name for r in resources[kind]}) == len(resources[kind]),
                    f"Duplicate {kind} in project namespace")
        server_ids = {r.id for r in resources["servers"]}
        router_ids = {r.id for r in resources["routers"]}
        network_ids = {r.id for r in resources["networks"]}
        owned_ports = {self.n(f"{h.name}-nic-{i}") for h in self.topology.get_all_hosts()
                       for i in range(1 + len(h.extra_interfaces))}
        data_ids = {n.id for n in resources["networks"] if n.name in {self.n(name) for name in DATA}}
        for port in resources["ports"]:
            compute = port.device_owner.startswith("compute:") and port.device_id in server_ids
            router = port.device_owner.startswith("network:router") and port.device_id in router_ids
            metadata = (port.network_id in network_ids and port.device_owner == "network:distributed"
                        and port.device_id == "ovnmeta-" + port.network_id)
            dhcp = (port.network_id in network_ids - data_ids and port.device_owner == "network:dhcp")
            unbound = not port.device_id and port.name in owned_ports
            require(compute or router or metadata or dhcp or unbound,
                    f"Foreign/unrecognized port {port.id} in experiment namespace")

    def namespace(self, existing):
        resources = self.resources()
        self.validate_namespace(resources)
        present = any(resources.values())
        require(present if existing else not present,
                "No deployment to adopt" if existing else "Project already exists; use --existing to verify and delete it")
        self.owned = True

    def provider(self):
        resources = self.resources()
        require({s.name for s in resources["servers"]} == self.server_names
                and all(s.status == "ACTIVE" for s in resources["servers"]), "Expected eight ACTIVE VMs")
        require({n.name for n in resources["networks"]} == self.network_names
                and {s.name for s in resources["subnets"]} == self.subnet_names,
                "Provider networks/subnets do not match the example")
        router = unique(resources["routers"], "experiment Neutron router")
        require(not router.routes, "Unexpected Neutron router routes")
        nets = {n.name: n for n in resources["networks"]}
        data_ids = {nets[self.n(name)].id for name in DATA}
        observations = []
        for name, cidr in DATA.items():
            subnet = unique([s for s in resources["subnets"] if s.name == self.n(name + "-subnet")], name)
            require(subnet.cidr == cidr and subnet.gateway_ip is None
                    and subnet.is_dhcp_enabled is False and subnet.host_routes == [],
                    f"{name}: Neutron data subnet has a routing shortcut")
            ports = [p for p in resources["ports"] if p.network_id == nets[self.n(name)].id]
            for port in ports:
                compute = port.device_owner.startswith("compute:") and port.device_id in {s.id for s in resources["servers"]}
                metadata = (port.device_owner == "network:distributed"
                            and port.device_id == "ovnmeta-" + port.network_id and port.fixed_ips == [])
                require(compute or metadata, f"{name}: unexpected data-network port {port.id} ({port.device_owner})")
            observations.append({"network": name, "cidr": subnet.cidr,
                                 "ports": [{"id": p.id, "owner": p.device_owner, "ips": p.fixed_ips} for p in ports]})
        attachments = [p for p in self.conn.network.ports(device_id=router.id)
                       if p.device_owner.startswith("network:router_interface")]
        control_ids = {n.id for n in resources["networks"]} - data_ids
        require({p.network_id for p in attachments} == control_ids
                and len(attachments) == 4, "Neutron router attachments must be only management/control")
        require(len(resources["fips"]) == 1, "Expected only the management floating IP")
        management = unique([s for s in resources["servers"] if s.name == self.n("management_host")], "management server")
        management_ports = {p.id for p in resources["ports"] if p.device_id == management.id}
        require(resources["fips"][0].port_id in management_ports, "Floating IP exposes a non-management port")
        self.mgmt = resources["fips"][0].floating_ip_address
        self.backend.routing_interfaces(self.topology)  # Existing fixed-IP/MAC/SG/port-security checks.
        self.report["provider"] = {"data": observations, "router": router.id,
                                   "control_networks": sorted(control_ids),
                                   "floating_ip": self.mgmt}
        self.save()

    def ssh(self, host):
        key = str(Path(self.config.ssh_key_path).expanduser().resolve())
        opts = ["-T", "-i", key, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "UserKnownHostsFile=" + str(self.output / "known_hosts")]
        proxy = shlex.join(["ssh", *opts, "-W", "%h:%p", "root@" + self.mgmt])
        return ["ssh", *opts, "-o", "ProxyCommand=" + proxy, "root@" + HOSTS[host][0].split("/")[0]]

    def batch(self, host, commands, timeout=20, record=True):
        script = ("import json,subprocess,os\nos.environ['LC_ALL']='C'\ncommands=" + repr(commands) +
                  "\nrows={}\nfor name,command in commands.items():\n"
                  " r=subprocess.run(command,capture_output=True,text=True,timeout=10)\n"
                  " rows[name]={'rc':r.returncode,'stdout':r.stdout,'stderr':r.stderr}\n"
                  "print(json.dumps(rows))\n")
        result = subprocess.run([*self.ssh(host), "python3 -c " + shlex.quote(script)],
                                capture_output=True, text=True, timeout=timeout)
        require(result.returncode == 0, f"{host}: SSH failed: {result.stderr.strip()}")
        rows = json.loads(result.stdout)
        if record:
            self.commands.write(json.dumps({"host": host, "commands": commands, "results": rows}) + "\n")
            self.commands.flush()
        return rows

    def run(self, host, argv, record=True):
        row = self.batch(host, {"command": argv}, record=record)["command"]
        require(row["rc"] == 0, f"{host}: {shlex.join(argv)}: {row['stderr'].strip()}")
        return row["stdout"].strip()

    def vty(self, host, *commands):
        return self.run(host, ["vtysh", *[x for c in commands for x in ["-c", c]]])

    def service(self, host, name, expected=None):
        commands = {"active": ["systemctl", "is-active", name],
                    "pid": ["systemctl", "show", name, "--property=MainPID", "--value"]}
        if expected is not None:
            commands["response"] = ["curl", "-4", "--noproxy", "*", "--max-time", "5",
                                    "--silent", "--show-error", "http://127.0.0.1:8080/health"]
        rows = self.batch(host, commands)
        require(all(r["rc"] == 0 for r in rows.values()), f"{host}: local service check failed")
        require(rows["active"]["stdout"].strip() == "active"
                and int(rows["pid"]["stdout"]) > 0, f"{host}: wrong service state")
        if expected is not None:
            require(rows["response"]["stdout"].strip() == expected,
                    f"{host}: wrong service response")
        return int(rows["pid"]["stdout"])

    def guests(self):
        snapshot = {}
        for host, expected in HOSTS.items():
            commands = {"addresses": ["ip", "-j", "-4", "address", "show"],
                        "routes": ["ip", "-j", "-4", "route", "show"],
                        "rules": ["ip", "-j", "-4", "rule", "show"],
                        "forwarding": ["sysctl", "-n", "net.ipv4.ip_forward"]}
            if host in ASNS:
                commands.update(active=["systemctl", "is-active", "frr"],
                                peers=["vtysh", "-c", "show bgp ipv4 unicast summary json"],
                                forward=["iptables", "-S", "FORWARD"],
                                guard=["iptables", "-S", "MHBENCH_FORWARD"],
                                nat=["iptables", "-t", "nat", "-S"])
            rows = self.batch(host, commands)
            require(all(r["rc"] == 0 for r in rows.values()), f"{host}: guest readback failed")
            addresses = json.loads(rows["addresses"]["stdout"])
            self.devices[host] = address_devices(addresses, expected)
            all_addresses = sorted(f"{a['local']}/{a['prefixlen']}" for r in addresses
                                   if r.get("ifname") != "docker0" for a in r.get("addr_info", []))
            wanted = expected + ["127.0.0.1/8"] + (
                [TARGET + "/24"] if host == "kali" and self.probe_started else [])
            require(all_addresses == sorted(wanted), f"{host}: unexpected or missing IPv4 addresses")
            control = self.devices[host][expected[0]]
            require(rows["forwarding"]["stdout"].strip() == ("1" if host in ASNS else "0"),
                    f"{host}: wrong forwarding setting")
            stable = {"addresses": all_addresses}
            if host in ASNS:
                require(rows["active"]["stdout"].strip() == "active", f"{host}: FRR inactive")
                peers = json.loads(rows["peers"]["stdout"])
                require(peers["as"] == ASNS[host] and set(peers["peers"]) == set(PEERS[host])
                        and all(p["state"] == "Established" for p in peers["peers"].values()),
                        f"{host}: expected Established peers")
                responses = [(self.devices[host]["10.250.0.9/30"], P)] if host == "attacker-router" else []
                check_guard(rows["forward"]["stdout"].strip(), rows["guard"]["stdout"].strip(),
                            rows["nat"]["stdout"].strip(), control, responses)
                stable["firewall"] = [rows[k]["stdout"] for k in ["forward", "guard", "nat"]]
            else:
                routes, rules = json.loads(rows["routes"]["stdout"]), json.loads(rows["rules"]["stdout"])
                gateway = GATEWAYS[host]
                host_routes(routes, rules, control, self.devices[host][expected[1]], gateway)
                data_ip = expected[1].split("/")[0]
                destination, source = (TARGET, SOURCE) if host == "client" else (SOURCE, data_ip)
                lookup = json.loads(self.run(host, ["ip", "-j", "-4", "route", "get", destination, "from", source]))
                require(len(lookup) == 1 and lookup[0].get("gateway") == gateway
                        and lookup[0].get("dev") == self.devices[host][expected[1]],
                        f"{host}: data lookup bypasses its AS gateway")
                stable.update(routes=routes, rules=rules)
            if host in ["origin-router", "transit-router"]:
                # Compare in memory, without logging arbitrary router configuration/passwords.
                stable["receiver_config"] = self.run(
                    host, ["vtysh", "-c", "show running-config"], record=False)
            if host in SERVICES:
                name, expected_response = SERVICES[host]
                stable["service_pid"] = self.service(host, name, expected_response)
            snapshot[host] = stable
        return snapshot

    def returns(self):
        kali_lan = DATA["attacker_lan"]
        checks = [
            ("origin-router", C, "10.250.0.2", 65002, 100),
            ("attacker-router", C, "10.250.0.5", 65002, 100),
            ("transit-router", kali_lan, "10.250.0.6", 65003, 200),
            ("origin-router", kali_lan, "10.250.0.2", "65002 65003", 100),
        ]
        for host, prefix, via, path, preference in checks:
            data = json.loads(self.vty(host, "show bgp ipv4 unicast " + prefix + " json"))
            route = json.loads(self.run(host, ["ip", "-j", "-4", "route", "show", "exact", prefix]))
            require(bgp_path(data, prefix, via, path, preference) and len(route) == 1
                    and route[0].get("gateway") == via, f"{host}: missing data return route for {prefix}")

    def transit(self, timeout=20):
        interface = self.devices["transit-router"]["198.18.0.1/24"]
        commands = {"p": ["vtysh", "-c", f"show bgp ipv4 unicast {P} json"],
                    "h": ["vtysh", "-c", f"show bgp ipv4 unicast {H} json"],
                    "kp": ["ip", "-j", "-4", "route", "show", "exact", P],
                    "kh": ["ip", "-j", "-4", "route", "show", "exact", H],
                    "lookup": ["ip", "-j", "-4", "route", "get", TARGET, "from", SOURCE, "iif", interface]}
        rows = self.batch("transit-router", commands, timeout=timeout)
        require(all(rows[k]["rc"] == 0 for k in ["p", "h", "kp", "kh"]), "Transit route readback failed")
        state = {k: json.loads(rows[k]["stdout"]) for k in ["p", "h", "kp", "kh"]}
        state["lookup"] = json.loads(rows["lookup"]["stdout"]) if rows["lookup"]["rc"] == 0 else []
        return state

    def wait_routes(self, mode):
        deadline = time.monotonic() + 60
        state = {}
        while time.monotonic() < deadline:
            state = self.transit(timeout=min(20, max(0.1, deadline - time.monotonic())))
            if mode == "broken":
                ready = not any([state["p"].get("paths"), state["h"].get("paths"), state["kp"], state["kh"]])
            else:
                via = "10.250.0.6" if mode == "announced" else "10.250.0.1"
                address = "10.250.0.5/30" if mode == "announced" else "10.250.0.2/30"
                device = self.devices["transit-router"][address]
                ready = (bgp_path(state["p"], P, "10.250.0.1", 65001, 200)
                         and len(state["kp"]) == 1 and state["kp"][0].get("gateway") == "10.250.0.1"
                         and len(state["lookup"]) == 1 and state["lookup"][0].get("gateway") == via
                         and state["lookup"][0].get("dev") == device)
                if mode == "announced":
                    ready = ready and bgp_path(state["h"], H, via, 65003, 200) and len(state["kh"]) == 1 and state["kh"][0].get("gateway") == via
                else:
                    ready = ready and not state["h"].get("paths") and not state["kh"]
            if ready:
                self.report["observations"][mode] = state
                self.save()
                return state
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        raise RuntimeError(f"Timed out waiting for {mode}; last observation: {state}")

    def start_captures(self):
        mapping = {"client": "198.18.0.1/24", "origin": "10.250.0.2/30",
                   "attacker": "10.250.0.5/30", "control": "10.200.2.10/24"}
        for role, address in mapping.items():
            interface = self.devices["transit-router"][address]
            expression = "tcp port 8080" if role == "control" else f"host {SOURCE} and host {TARGET} and tcp port 8080"
            argv = ["tcpdump", "-nn", "-tt", "-l", "--immediate-mode", "-i", interface, expression]
            command = "python3 -c " + shlex.quote(CAPTURE) + " " + shlex.join(argv)
            capture = Capture([*self.ssh("transit-router"), command], self.output / (role + ".tcpdump"))
            self.captures[role] = capture
            capture.ready()  # Registered before readiness checks so failed startup is also cleaned up.

    def stop_captures(self):
        errors = []
        for role, capture in list(self.captures.items()):
            try:
                capture.stop()
            except Exception as exc:
                errors.append(f"{role}: {exc}")
            finally:
                del self.captures[role]
        require(not errors, "; ".join(errors))

    def probe(self, stage, expected=None, wan=None):
        require(all(c.process.poll() is None for c in self.captures.values()), "A capture stopped during measurement")
        row = self.batch("client", {"probe": ["curl", "-4", "--noproxy", "*", "--interface", SOURCE,
                    "--connect-timeout", "2", "--max-time", "5", "--silent", "--show-error",
                    "--write-out", "\nMHB_SOCKET %{local_ip} %{local_port} %{remote_ip} %{remote_port}\n",
                    f"http://{TARGET}:8080/health"]})["probe"]
        self.report.setdefault("probes", {})[stage] = row
        if expected is None:
            require(row["rc"] in [7, 28], f"{stage}: expected connection failure, got {row}")
        else:
            match = re.fullmatch(r"(ORIGIN|ATTACKER)\s+MHB_SOCKET (\S+) (\d+) (\S+) (\d+)\s*", row["stdout"])
            require(row["rc"] == 0 and match is not None, f"{stage}: invalid curl result {row}")
            response, local, port, remote, remote_port = match.groups()
            require(response == expected and local == SOURCE and remote == TARGET and remote_port == "8080",
                    f"{stage}: wrong response or socket endpoints")
            require(int(port) not in {p["port"] for p in self.probes.values()}, "Ambiguous repeated probe source port")
            self.probes[stage] = {"port": int(port), "wan": wan, "response": response}
        self.save()

    def neighbor(self, shutdown):
        self.vty("origin-router", "configure terminal", "router bgp 65001",
                 ("" if shutdown else "no ") + "neighbor 10.250.0.2 shutdown", "end")

    def announcement(self, enabled):
        self.vty("attacker-router", "configure terminal", "router bgp 65003", "address-family ipv4 unicast",
                 ("" if enabled else "no ") + "network " + H, "end")

    def start_probe(self):
        """Install the runner's temporary attacker-side responder and its delivery route."""
        self.run("kali", ["ip", "addr", "replace", TARGET + "/24", "dev", "lo"])
        command = "nohup python3 -c " + shlex.quote(PROBE) + \
                  " >/tmp/mhbench-attacker-probe.log 2>&1 & echo $!"
        self.probe_pid = int(self.run("kali", ["sh", "-c", command]).strip().splitlines()[-1])
        self.probe_started = True
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            row = self.batch("kali", {"ready": ["curl", "-4", "--noproxy", "*", "--max-time", "2",
                                               "--silent", "--show-error", f"http://{TARGET}:8080/health"]},
                             record=False)["ready"]
            if row["rc"] == 0 and row["stdout"].strip() == "ATTACKER":
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Attacker responder did not become ready")
        self.vty("attacker-router", "configure terminal", "ip route " + H + " 10.250.0.10", "end")
        self.routed = True
        self.save()

    def stop_probe(self):
        """Remove the temporary responder and delivery route; idempotent."""
        errors = []
        if self.probe_pid:
            try:
                self.run("kali", ["sh", "-c", f"kill {self.probe_pid} 2>/dev/null || true"])
            except Exception as exc:
                errors.append(f"stop Kali responder: {exc}")
            self.probe_pid = None
        if self.routed:
            try:
                self.vty("attacker-router", "configure terminal", "no ip route " + H + " 10.250.0.10", "end")
            except Exception as exc:
                errors.append(f"remove H route: {exc}")
            self.routed = False
        try:
            self.run("kali", ["sh", "-c", f"ip addr del {TARGET}/24 dev lo 2>/dev/null || true"])
        except Exception as exc:
            errors.append(f"remove Kali {TARGET}: {exc}")
        self.probe_started = False
        self.save()
        require(not errors, "; ".join(errors))

    def verify_baseline(self):
        """Non-mutating checks against an existing deployment; never changes BGP or ownership."""
        LOG.info("Verifying the existing deployment's baseline state")
        self.provider()
        self.guests()
        self.returns()
        self.wait_routes("initial")
        self.probe("verify-only", "ORIGIN", "origin")
        self.report["verify_only"] = True
        self.save()
        LOG.info("Baseline verification passed without mutation")

    def verify(self):
        LOG.info("Checking provider and guest readiness")
        self.provider()
        self.run("transit-router", ["tcpdump", "--version"])
        self.start_probe()
        baseline = self.guests()
        self.returns()
        self.wait_routes("initial")
        self.start_captures()
        self.probe("initial", "ORIGIN", "origin")
        LOG.info("Checking loss of BGP cannot fall back through management")
        control = self.devices["transit-router"]["10.200.2.10/24"]
        counter = lambda: drop_counter(self.run("transit-router", ["iptables", "-nvxL", "MHBENCH_FORWARD"]), control)
        self.shutdown = True
        try:
            self.neighbor(True)
            state = self.wait_routes("broken")
            before = counter()
            self.probe("broken")
            if state["lookup"]:
                require(state["lookup"][0].get("dev") == control, "Broken route selected an unexpected interface")
                require(counter() > before, "Control-facing DROP counter did not increase")
            for host in HOSTS:
                self.run(host, ["true"])
            self.service("server", "mhbench-portal", "ORIGIN")
            self.service("vault", "mhbench-vault", "VAULT")
        finally:
            self.neighbor(False)
            self.shutdown = False
        self.wait_routes("restored")
        require(self.guests() == baseline, "State changed after neighbor shutdown/restoration")
        self.returns()
        self.probe("baseline", "ORIGIN", "origin")
        LOG.info("Announcing the controlled /24")
        self.announced = True
        self.announcement(True)
        self.wait_routes("announced")
        self.probe("announced", "ATTACKER", "attacker")
        require(self.guests() == baseline, "Receiver/host/service/firewall state changed during announcement")
        self.returns()
        LOG.info("Withdrawing the /24 and requiring full restoration")
        self.announcement(False)
        self.announced = False
        self.wait_routes("withdrawn")
        self.probe("withdrawn", "ORIGIN", "origin")
        require(self.guests() == baseline, "State changed after withdrawal")
        self.returns()
        self.stop_probe()
        self.stop_captures()
        self.report["packet_paths"] = capture_evidence(
            {role: self.output / (role + ".tcpdump") for role in ["client", "origin", "attacker", "control"]}, self.probes)
        self.provider()
        self.save()
        LOG.info("All BGP, forwarding, isolation, and restoration checks passed")

    def cleanup(self):
        errors = self.report["cleanup_errors"]
        for needed, action, label in [(self.announced, lambda: self.announcement(False), "withdraw H"),
                                      (self.shutdown, lambda: self.neighbor(False), "restore origin peer"),
                                      (self.probe_started or self.routed, self.stop_probe, "stop attacker responder"),
                                      (bool(self.captures), self.stop_captures, "stop captures")]:
            if needed:
                try:
                    action()
                except Exception as exc:
                    errors.append(f"{label}: {exc}")
        if self.owned:
            LOG.info("Tearing down project %s", self.project)
            try:
                self.validate_namespace(self.resources())
                self.orchestrator.teardown(self.topology)
            except Exception as exc:
                errors.append(f"teardown: {exc}")
            try:
                remaining = {k: [r.id for r in v] for k, v in self.resources().items() if v}
                self.report["remaining_resources"] = remaining
                if self.initial_fip_ids is not None:
                    unassigned = [f.id for f in self.conn.network.ips(project_id=self.pid)
                                  if f.id not in self.initial_fip_ids and not f.port_id]
                    self.report["new_unassigned_floating_ips"] = unassigned
                    require(not unassigned, f"Unassigned new floating IPs need ownership inspection: {unassigned}")
                require(not remaining, f"Experiment resources remain: {remaining}")
            except Exception as exc:
                errors.append(f"absence check: {exc}")
        self.save()
        self.commands.close()
        return not errors

    def save(self):
        (self.output / "summary.json").write_text(json.dumps(self.report, indent=2) + "\n")


def load_topology(config):
    require(config.backend == "openstack", "This experiment requires the OpenStack backend")
    parser = JsonSpecParser()
    topology = parser.parse(REPO / "environments/non-generated/bgp_three_as.json")
    errors = parser.validate(topology, OfflineRegistryService(config), OnlineRegistryService(config), config)
    require(not errors, "; ".join(errors))
    actual = {h.name: [f"{h.ip_address}/{topology.get_subnet_for_host(h).cidr.prefixlen}"] +
              [f"{i.ip_address}/{topology.get_subnet_by_name(i.subnet).cidr.prefixlen}" for i in h.extra_interfaces]
              for h in topology.get_all_hosts()}
    require(actual == HOSTS, "Example guest/address contract changed; update the fixed verifier deliberately")
    require(topology.get_host_by_name("kali").extra_interfaces[0].response_prefixes == [ipaddress.IPv4Network(P)],
            "Kali reply-source permission must match the origin aggregate")
    require({r.host: r.asn for r in topology.routing.routers} == ASNS, "Example ASNs changed")
    require({s.name: str(s.cidr) for s in topology.get_all_subnets() if s.name in topology.routing.data_subnet_names(topology)} == DATA,
            "Example data subnets changed")
    out_policy = next((p for p in topology.routing.policies if p.name == "attacker_out"), None)
    require(out_policy is not None and any(
                str(rule.prefix) == P and rule.max_prefix_length == 24 for rule in out_policy.rules),
            "Attacker export policy must be the generic P/max-24 form")
    for router in topology.routing.routers:
        require(sorted(p["address"] for p in router_peers(topology, router)) == sorted(PEERS[router.host]),
                "Example peers changed")
    return topology


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=REPO / "config/config.yaml")
    parser.add_argument("--project-name", default="bgp-demo")
    parser.add_argument("--existing", action="store_true", help="Adopt an existing deployment; DELETE it after verification")
    parser.add_argument("--verify-only", action="store_true",
                        help="Adopt an existing deployment, run only non-mutating baseline checks, and never tear it down")
    parser.add_argument("--output-dir", type=Path, help="New directory for retained evidence (must not exist)")
    args = parser.parse_args(argv)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,60}", args.project_name), "Invalid project name")
    if args.verify_only and args.existing:
        raise SystemExit("--verify-only and --existing are mutually exclusive")
    adopt = args.existing or args.verify_only
    config_path = args.config.resolve()
    output = (args.output_dir or REPO.parent / ".validation/bgp-three-as" /
              (args.project_name + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ"))).resolve()
    os.chdir(REPO)
    config = Config.load(config_path)
    topology = load_topology(config)
    require(shutil.which("ssh") is not None, "SSH client is required")
    if not adopt:
        require(shutil.which("ansible-playbook") is not None, "ansible-playbook is required; use uv run python")
    require(Path(config.ssh_key_path).expanduser().is_file(), "Configured SSH private key file is missing")
    output.mkdir(parents=True, mode=0o700)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.StreamHandler(), logging.FileHandler(output / "run.log")])
    revision = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True)
    experiment = Experiment(config, topology, args.project_name, output)
    experiment.report.update(revision=revision.stdout.strip(), project=args.project_name,
                             existing=args.existing, verify_only=args.verify_only)
    def interrupted(signum, frame):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise KeyboardInterrupt(f"signal {signum}")
    old_term = signal.signal(signal.SIGTERM, interrupted)
    old_int = signal.signal(signal.SIGINT, interrupted)
    succeeded = False
    try:
        experiment.namespace(adopt)
        if args.verify_only:
            experiment.owned = False
            experiment.verify_baseline()
        else:
            if not args.existing:
                LOG.info("Provisioning and configuring project %s", args.project_name)
                experiment.mgmt = experiment.orchestrator.provision(topology)
                experiment.orchestrator.configure(topology, experiment.mgmt)
            experiment.verify()
        succeeded = True
    except (Exception, KeyboardInterrupt) as exc:
        experiment.report["error"] = f"{type(exc).__name__}: {exc}"
        LOG.exception("Experiment failed")
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            clean = experiment.cleanup()
        finally:
            signal.signal(signal.SIGTERM, old_term)
            signal.signal(signal.SIGINT, old_int)
    experiment.report["passed"] = succeeded and clean
    experiment.save()
    LOG.info("Result: %s; evidence: %s", "PASS" if succeeded and clean else "FAIL", output)
    return 0 if succeeded and clean else 1


if __name__ == "__main__":
    sys.exit(main())
