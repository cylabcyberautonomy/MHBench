"""Translate MHBench v1/v2 environment JSONs to v3_MHBench format.

Translation rules:
- Drop UUIDs, users, is_attacker, is_decoy, gateway_ip, is_external
- Map os_type → vm_type based on the host's vulnerability set (see VULN_VM_TYPE_MAP)
- Playbooks baked into a vm_type are not repeated in the per-instance playbooks list;
  only setup_ssh_keys and add_data (which need host-pair/path args) stay per-instance
- Map flavor p2.tiny → m1.small
- Convert goals → add_data playbook entries
- Convert attacker_host → attacker_subnet with kali_running host
"""

import json
import sys
from pathlib import Path

SRC_DIR = Path(__file__).parent.parent / "MHBench/src/environments/generated"
DST_DIR = Path(__file__).parent / "environments/generated"

FLAVOR_MAP = {
    "p2.tiny": "m1.small",
}

# Map MHBench playbook paths to v3 playbook names
PLAYBOOK_PATH_MAP = {
    "apacheStruts/setupStruts.yml": "setup_struts",
    "setupStruts.yml": "setup_struts",
    "NetcatShell.yml": "netcat_shell",
    "writeablePasswd.yml": "writeable_passwd",
    "setup_ssh_keys.yml": "setup_ssh_keys",
    "addData.yml": "add_data",
    "sudobaron/sudobaron.yml": "sudobaron",
    "sudobypass/sudobypass.yml": "sudobypass",
    "sudoedit/sudoedit.yml": "sudoedit",
}

# Playbooks that are baked into a vm_type and must NOT appear in the per-instance list.
# setup_ssh_keys and add_data stay per-instance because they need host-pair / path args.
BAKED_PLAYBOOKS = {"setup_struts", "netcat_shell", "writeable_passwd", "sudobaron", "sudobypass", "sudoedit"}

# Maps frozenset of baked-vulnerability names → vm_type in the online registry.
# Hosts with os_type KaliLinux always map to kali_running regardless of this table.
VULN_VM_TYPE_MAP: dict[frozenset, str] = {
    frozenset(): "ubuntu_base_running",
    frozenset({"setup_struts"}): "webserver_running",
    frozenset({"netcat_shell"}): "ubuntu_netcat_running",
    frozenset({"writeable_passwd"}): "ubuntu_writeable_running",
    frozenset({"sudobaron"}): "ubuntu_sudobaron_running",
    frozenset({"netcat_shell", "setup_struts"}): "webserver_netcat_running",
    frozenset({"setup_struts", "writeable_passwd"}): "webserver_writeable_running",
    frozenset({"setup_struts", "sudobaron"}): "webserver_sudobaron_running",
    frozenset({"netcat_shell", "writeable_passwd"}): "ubuntu_netcat_writeable_running",
    frozenset({"netcat_shell", "sudobaron"}): "ubuntu_netcat_sudobaron_running",
    frozenset({"netcat_shell", "setup_struts", "writeable_passwd"}): "webserver_netcat_writeable_running",
    frozenset({"netcat_shell", "setup_struts", "sudobaron"}): "webserver_netcat_sudobaron_running",
}

ATTACKER_SUBNET_CIDR = "10.0.0.0/24"
ATTACKER_IP = "10.0.0.10"


def map_playbook_path(path: str) -> str | None:
    for suffix, name in PLAYBOOK_PATH_MAP.items():
        if path.endswith(suffix):
            return name
    return None


def build_ip_to_host(topology: dict) -> dict[str, str]:
    """Build a mapping from IP address string → host name."""
    ip_map = {}
    for network in topology.get("networks", []):
        for subnet in network.get("subnets", []):
            for host in subnet.get("hosts", []):
                if ip := host.get("ip_address"):
                    ip_map[str(ip)] = host["name"]
    if ah := topology.get("attacker_host"):
        if ip := ah.get("ip_address"):
            ip_map[str(ip)] = ah["name"]
    return ip_map


def host_vm_type(host: dict) -> str:
    """Determine the v3 vm_type for a host based on its os_type and vulnerability set."""
    os_type = host.get("os_type", "Ubuntu20")
    if os_type == "KaliLinux":
        return "kali_running"

    baked_vulns = set()
    for vuln in host.get("vulnerabilities", []):
        pb = map_playbook_path(vuln.get("playbook_path", ""))
        if pb and pb in BAKED_PLAYBOOKS:
            baked_vulns.add(pb)

    vm_type = VULN_VM_TYPE_MAP.get(frozenset(baked_vulns))
    if vm_type is None:
        print(
            f"  WARNING: no vm_type for vuln set {baked_vulns} on host '{host['name']}', "
            "falling back to ubuntu_base_running",
            file=sys.stderr,
        )
        return "ubuntu_base_running"
    return vm_type


def vuln_to_playbook(vuln: dict, host_name: str, ip_to_host: dict) -> dict | None:
    """Convert a MHBench vulnerability to a v3 PlaybookRef.

    Returns None for vulnerabilities that are baked into the vm_type (no per-instance entry needed),
    and for unknown playbook paths.
    """
    path = vuln.get("playbook_path", "")
    pb_name = map_playbook_path(path)
    if pb_name is None:
        print(f"  WARNING: unknown playbook path '{path}', skipping", file=sys.stderr)
        return None

    # These are baked into the vm_type — no per-instance playbook needed
    if pb_name in BAKED_PLAYBOOKS:
        return None

    if pb_name == "setup_ssh_keys":
        from_ip = vuln.get("from_host_ip", "")
        to_ip = vuln.get("to_host_ip", "")
        from_host = ip_to_host.get(from_ip, from_ip)
        to_host = ip_to_host.get(to_ip, to_ip)
        return {
            "name": "setup_ssh_keys",
            "args": {
                "host": from_host,
                "host_user": vuln.get("from_user", ""),
                "follower": to_host,
                "follower_user": vuln.get("to_user", ""),
            },
        }

    return None


def goal_to_playbook(goal: dict, ip_to_host: dict) -> dict | None:
    """Convert a MHBench data_exfiltration goal to an add_data PlaybookRef."""
    if goal.get("type") != "data_exfiltration":
        return None
    host_ip = goal.get("host_ip", "")
    host_name = ip_to_host.get(host_ip, host_ip)
    return {
        "name": "add_data",
        "args": {
            "host": host_name,
            "host_user": goal.get("host_user", "root"),
            "path": goal.get("dst_path", ""),
        },
    }


def translate_host(host: dict) -> dict:
    flavor = host.get("flavor", "m1.small")
    return {
        "name": host["name"],
        "vm_type": host_vm_type(host),
        "flavor": FLAVOR_MAP.get(flavor, flavor),
        **({"ip_address": host["ip_address"]} if host.get("ip_address") else {}),
    }


def translate_subnet(subnet: dict) -> dict:
    out = {
        "name": subnet["name"],
        "cidr": subnet["cidr"],
        "dns_servers": subnet.get("dns_servers", ["8.8.8.8"]),
        "hosts": [translate_host(h) for h in subnet.get("hosts", [])],
    }
    if subnet.get("external"):
        out["external"] = True
    return out


def translate_network(network: dict) -> dict:
    return {
        "name": network["name"],
        "description": network.get("description", ""),
        "subnets": [translate_subnet(s) for s in network.get("subnets", [])],
    }


def build_attacker_subnet(attacker_host: dict) -> dict:
    return {
        "name": "attacker_subnet",
        "cidr": ATTACKER_SUBNET_CIDR,
        "dns_servers": ["8.8.8.8"],
        "hosts": [
            {
                "name": attacker_host.get("name", "attacker"),
                "vm_type": "kali_running",
                "flavor": "m2.large",
                "ip_address": ATTACKER_IP,
            }
        ],
    }


def playbook_key(pb: dict) -> tuple:
    return (pb["name"], json.dumps(pb.get("args", {}), sort_keys=True))


def translate(topology: dict) -> dict:
    ip_to_host = build_ip_to_host(topology)

    networks = [translate_network(n) for n in topology.get("networks", [])]

    if attacker_host := topology.get("attacker_host"):
        if networks:
            networks[0]["subnets"].append(build_attacker_subnet(attacker_host))

    subnet_connections = topology.get("subnet_connections", [])

    seen: set[tuple] = set()
    playbooks: list[dict] = []

    def add_pb(pb):
        if pb is None:
            return
        key = playbook_key(pb)
        if key not in seen:
            seen.add(key)
            playbooks.append(pb)

    # Phase 1: create non-root users before any playbook that depends on them
    for network in topology.get("networks", []):
        for subnet in network.get("subnets", []):
            for host in subnet.get("hosts", []):
                for user in host.get("users", []):
                    if user["username"] == "root":
                        continue
                    add_pb({
                        "name": "create_user",
                        "args": {
                            "host": host["name"],
                            "user": user["username"],
                            "password": user["password"],
                            "group": user["username"],
                        },
                    })

    # Phase 2: vulnerability and goal playbooks (setup_ssh_keys, add_data, …)
    for network in topology.get("networks", []):
        for subnet in network.get("subnets", []):
            for host in subnet.get("hosts", []):
                for vuln in host.get("vulnerabilities", []):
                    add_pb(vuln_to_playbook(vuln, host["name"], ip_to_host))

    for goal in topology.get("goals", []):
        add_pb(goal_to_playbook(goal, ip_to_host))

    return {
        "name": topology["name"],
        "networks": networks,
        "subnet_connections": subnet_connections,
        "playbooks": playbooks,
    }


def main():
    DST_DIR.mkdir(parents=True, exist_ok=True)

    src_files = sorted(SRC_DIR.glob("*.json"))
    if not src_files:
        print(f"No JSON files found in {SRC_DIR}", file=sys.stderr)
        sys.exit(1)

    for src_path in src_files:
        print(f"Translating {src_path.name} ...", end=" ")
        with open(src_path) as f:
            topology = json.load(f)

        v3 = translate(topology)

        dst_path = DST_DIR / src_path.name
        with open(dst_path, "w") as f:
            json.dump(v3, f, indent=2)
        print(f"→ {dst_path.relative_to(Path(__file__).parent)}")

    print(f"\nDone. {len(src_files)} environment(s) written to {DST_DIR}")


if __name__ == "__main__":
    main()
