#!/usr/bin/env python3
"""Prepare and verify the guest network managed by the routing playbook."""
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import sys


def ip_json(*args):
    return json.loads(subprocess.check_output(["ip", "-j", *args], text=True))


def devices(network):
    links = ip_json("link", "show")
    result = {}
    for name, entry in network["network"]["ethernets"].items():
        mac = entry["match"]["macaddress"].lower()
        matches = [link["ifname"] for link in links if link.get("address", "").lower() == mac]
        if len(matches) != 1:
            raise ValueError("Expected one guest NIC for " + name + " (" + mac + ")")
        result[name] = matches[0]
    return result


def prepare(payload):
    network = payload["network"]
    names = devices(network)
    control = network["network"]["ethernets"]["mhb_control"]
    link_local = ipaddress.IPv4Network("169.254.0.0/16")
    for route in ip_json("-4", "route", "show"):
        if route.get("dst") in (None, "default") or not route.get("gateway"):
            continue
        if route.get("dev") == names["mhb_control"] and ipaddress.IPv4Network(route["dst"]).subnet_of(link_local):
            destination = ipaddress.IPv4Network(route["dst"])
            data = [ipaddress.IPv4Interface(a).network for key, nic in network["network"]["ethernets"].items()
                    if key != "mhb_control" for a in nic["addresses"]]
            if any(destination.overlaps(prefix) for prefix in data):
                raise ValueError("Provider control route overlaps the data plane")
            entry = {"to": str(destination), "via": route["gateway"]}
            if entry not in control["routes"]:
                control["routes"].append(entry)
    hostname = payload.get("c2_hostname")
    if hostname:
        prefixes = [ipaddress.IPv4Network(p) for p in payload["control_prefixes"]]
        addresses = {ipaddress.IPv4Address(row[4][0])
                     for row in socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)}
        if not addresses or any(not any(a in p for p in prefixes) for a in addresses):
            raise ValueError("C2 IPv4 addresses are not covered by control routes")
    if "ID=kali" in open("/etc/os-release", encoding="utf-8").read():
        network["network"]["renderer"] = "ifupdown"
    return network



def apply_ifupdown(network):
    names = devices(network)
    ethernets = network["network"]["ethernets"]
    control = ethernets["mhb_control"]
    data_name = next(name for name in ethernets if name != "mhb_control")
    data = ethernets[data_name]

    lines = ["auto lo", "iface lo inet loopback", ""]
    for entry, ifname in ((control, names["mhb_control"]), (data, names[data_name])):
        lines += [f"auto {ifname}", f"iface {ifname} inet static"]
        for address in entry["addresses"]:
            lines.append(f"    address {address}")
        default = next((route["via"] for route in entry.get("routes", [])
                        if route["to"] in ("0.0.0.0/0", "default")), None)
        if default:
            lines.append(f"    gateway {default}")
        for route in entry.get("routes", []):
            if route["to"] in ("0.0.0.0/0", "default"):
                continue
            lines.append(f"    post-up ip route add {route['to']} via {route['via']} dev {ifname}")
            lines.append(f"    pre-down ip route del {route['to']} via {route['via']} dev {ifname} || true")
        lines.append("")
    Path("/etc/network/interfaces").write_text("\n".join(lines), encoding="utf-8")
    subprocess.run(["systemctl", "restart", "networking"], check=True)
    return {"applied": True}


def verify(network):
    names = devices(network)
    addresses = ip_json("-4", "address", "show")
    routes = ip_json("-4", "route", "show")
    for route in routes:
        destination = "0.0.0.0/0" if route.get("dst") in (None, "default") else route["dst"]
        route["dst"] = str(ipaddress.IPv4Network(destination))
    expected_defaults = []
    for name, entry in network["network"]["ethernets"].items():
        actual = next(a for a in addresses if a["ifname"] == names[name])
        present = {a["local"] + "/" + str(a["prefixlen"])
                   for a in actual["addr_info"] if a["family"] == "inet"}
        if not set(entry["addresses"]) <= present:
            raise ValueError("Guest data/control addresses do not match " + name)
        for route in entry.get("routes", []):
            if route["to"] == "0.0.0.0/0":
                expected_defaults.append(route)
            if not any(r["dst"] == str(ipaddress.IPv4Network(route["to"]))
                       and r.get("gateway") == route["via"] and r.get("dev") == names[name] for r in routes):
                raise ValueError("Missing guest route " + str(route))
    defaults = [r for r in routes if r["dst"] == "0.0.0.0/0"]
    if len(expected_defaults) != 1 or len(defaults) != 1:
        raise ValueError("Guest must have exactly one default route")
    return {"verified": True}


if __name__ == "__main__":
    payload = json.load(sys.stdin)
    if sys.argv[1] == "prepare":
        result = prepare(payload)
    elif sys.argv[1] == "apply-ifupdown":
        result = apply_ifupdown(payload)
    elif sys.argv[1] == "verify":
        result = verify(payload)
    else:
        raise SystemExit("Expected prepare, apply-ifupdown, or verify")
    json.dump(result, sys.stdout)
    print()
