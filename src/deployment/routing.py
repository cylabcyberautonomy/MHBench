from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

import yaml

from config.config import Config
from src.abstractions.network import NetworkTopology
from src.abstractions.routing import Router


def router_peers(topology: NetworkTopology, router: Router) -> list[dict]:
    peers = []
    routers = {r.host: r for r in topology.routing.routers}
    for peering in topology.routing.peerings:
        local = next((e for e in peering.endpoints if e.router == router.host), None)
        if local is None:
            continue
        remote = next(e for e in peering.endpoints if e.router != router.host)
        local_ip = next(i.ip_address for i in topology.get_host_by_name(router.host).extra_interfaces
                        if i.subnet == peering.subnet)
        remote_ip = next(i.ip_address for i in topology.get_host_by_name(remote.router).extra_interfaces
                         if i.subnet == peering.subnet)
        peers.append({"address": str(remote_ip), "local_address": str(local_ip),
                      "asn": routers[remote.router].asn, "import_policy": local.import_policy,
                      "export_policy": local.export_policy})
    return peers


def render_frr(topology: NetworkTopology, router: Router) -> str:
    peers = router_peers(topology, router)
    used = {p[key] for p in peers for key in ("import_policy", "export_policy")}
    lines = ["frr defaults traditional", "!"]
    for policy in topology.routing.policies:
        if policy.name not in used:
            continue
        for index, rule in enumerate(policy.rules, 1):
            sequence = index * 10
            name = f"mhb_{policy.name}_{sequence}"
            minimum, maximum = rule.prefix_lengths
            match = str(rule.prefix)
            if minimum > rule.prefix.prefixlen:
                match += f" ge {minimum}"
            if maximum > rule.prefix.prefixlen and (minimum == rule.prefix.prefixlen or maximum < 32):
                match += f" le {maximum}"
            lines += [f"ip prefix-list {name} seq 5 permit {match}",
                      f"route-map {policy.name} {rule.action} {sequence}",
                      f" match ip address prefix-list {name}"]
            if rule.local_preference is not None:
                lines.append(f" set local-preference {rule.local_preference}")
            lines += ["exit", "!"]
        lines += [f"route-map {policy.name} deny {(len(policy.rules) + 1) * 10}", "exit", "!"]
    lines += [f"router bgp {router.asn}", f" bgp router-id {router.router_id}",
              " bgp ebgp-requires-policy", " bgp network import-check"]
    for peer in peers:
        lines += [f" neighbor {peer['address']} remote-as {peer['asn']}",
                  f" neighbor {peer['address']} update-source {peer['local_address']}",
                  f" neighbor {peer['address']} enforce-first-as"]
    lines.append(" address-family ipv4 unicast")
    for prefix in router.advertised_prefixes:
        lines.append(f"  network {prefix}")
    for peer in peers:
        lines += [f"  neighbor {peer['address']} activate",
                  f"  neighbor {peer['address']} route-map {peer['import_policy']} in",
                  f"  neighbor {peer['address']} route-map {peer['export_policy']} out"]
    lines += [" exit-address-family", "exit", "!"]
    return "\n".join(lines) + "\n"


def guest_configurations(topology: NetworkTopology, config: Config,
                         interfaces: dict[str, dict]) -> dict[str, dict]:
    routing = topology.routing
    data_names = routing.data_subnet_names(topology)
    routers = {r.host: r for r in routing.routers}
    gateways = {g.host: g for g in routing.host_gateways}
    controls = {s.cidr for s in topology.get_all_subnets() if s.name not in data_names}
    controls.add(IPv4Network(config.management.cidr))
    controls.update(routing.control_routes)
    c2_hostname = None
    if config.c2c:
        try:
            controls.add(IPv4Network(f"{IPv4Address(config.c2c.ip)}/32"))
        except ValueError:
            c2_hostname = config.c2c.ip
    result = {}
    for name, actual in interfaces.items():
        host = topology.get_host_by_name(name)
        primary = topology.get_subnet_for_host(host)
        gateway = IPv4Address(actual["control_gateway"])
        if gateway not in primary.cidr:
            raise ValueError(f"Control gateway for {name!r} is outside its subnet.")
        prefixes = set(controls)
        for dns in primary.dns_servers:
            resolver = IPv4Address(dns)
            if any(resolver in s.cidr for s in topology.get_all_subnets() if s.name in data_names):
                raise ValueError("Control DNS servers must be outside the data plane.")
            prefixes.add(IPv4Network(f"{resolver}/32"))
        is_router = name in routers
        control = {"match": {"macaddress": actual["macs"][primary.name]},
                   "dhcp4": False, "dhcp6": False, "accept-ra": False, "link-local": [],
                   "addresses": [f"{host.ip_address}/{primary.cidr.prefixlen}"]}
        if primary.dns_servers:
            control["nameservers"] = {"addresses": primary.dns_servers}
        if is_router:
            control["routes"] = [{"to": "0.0.0.0/0", "via": str(gateway)}]
        else:
            control["routes"] = [{"to": str(p), "via": str(gateway)}
                                 for p in sorted(prefixes, key=str) if not p.subnet_of(primary.cidr)]
        ethernets = {"mhb_control": control}
        for index, interface in enumerate(host.extra_interfaces):
            subnet = topology.get_subnet_by_name(interface.subnet)
            entry = {"match": {"macaddress": actual["macs"][interface.subnet]},
                     "dhcp4": False, "dhcp6": False, "accept-ra": False, "link-local": [],
                     "addresses": [f"{interface.ip_address}/{subnet.cidr.prefixlen}"]}
            if name in gateways:
                entry["routes"] = [{"to": "0.0.0.0/0", "via": str(gateways[name].gateway)}]
            ethernets[f"mhb_data_{index}"] = entry
        router = routers.get(name)
        response_sources = []
        if router:
            for endpoint in routing.host_gateways:
                if any(i.subnet == endpoint.subnet and i.ip_address == endpoint.gateway
                       for i in host.extra_interfaces):
                    interface = topology.get_host_by_name(endpoint.host).extra_interfaces[0]
                    response_sources.extend({"mac": actual["macs"][endpoint.subnet].lower(),
                                             "prefix": str(p)} for p in interface.response_prefixes)
        result[name] = {
            "routing_router": is_router,
            "routing_control_mac": actual["macs"][primary.name].lower(),
            "routing_response_sources": response_sources,
            "routing_netplan": yaml.safe_dump({"network": {"version": 2, "renderer": "networkd",
                                                         "ethernets": ethernets}}, sort_keys=False),
            "routing_frr": render_frr(topology, router) if router else "",
            "routing_peers": [p["address"] for p in router_peers(topology, router)] if router else [],
            "routing_origins": [str(p) for p in router.advertised_prefixes] if router else [],
            "routing_c2_hostname": c2_hostname,
            "routing_control_prefixes": [str(p) for p in sorted(prefixes, key=str)],
        }
    expected = set(routers) | set(gateways)
    if set(result) != expected:
        raise ValueError("Provider interface readback must cover every routing participant.")
    return result
