from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

if TYPE_CHECKING:
    from src.abstractions.network import NetworkTopology

PolicyName = Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,62}$")]


class PrefixRule(BaseModel):
    model_config = {"extra": "forbid"}

    prefix: IPv4Network
    action: Literal["permit", "deny"]
    min_prefix_length: int | None = Field(default=None, ge=0, le=32, strict=True)
    max_prefix_length: int | None = Field(default=None, ge=0, le=32, strict=True)
    local_preference: int | None = Field(default=None, ge=0, le=4294967295, strict=True)

    @property
    def prefix_lengths(self) -> tuple[int, int]:
        minimum = self.prefix.prefixlen if self.min_prefix_length is None else self.min_prefix_length
        maximum = self.max_prefix_length
        if maximum is None:
            maximum = self.prefix.prefixlen if self.min_prefix_length is None else 32
        return minimum, maximum

    @model_validator(mode="after")
    def validate_rule(self) -> PrefixRule:
        minimum, maximum = self.prefix_lengths
        if not self.prefix.prefixlen <= minimum <= maximum <= 32:
            raise ValueError("prefix length bounds must lie between the prefix length and 32")
        if self.action == "deny" and self.local_preference is not None:
            raise ValueError("local_preference applies only to permitted imports")
        return self


class RoutingPolicy(BaseModel):
    model_config = {"extra": "forbid"}

    name: PolicyName
    rules: list[PrefixRule]
    default_action: Literal["deny"]


class Router(BaseModel):
    model_config = {"extra": "forbid"}

    host: str
    asn: int = Field(ge=1, le=4294967294, strict=True)
    router_id: IPv4Address
    advertised_prefixes: list[IPv4Network] = Field(default_factory=list)

    @field_validator("asn")
    @classmethod
    def validate_asn(cls, value: int) -> int:
        if value in {23456, 65535}:
            raise ValueError("reserved ASNs are not supported")
        return value

    @field_validator("router_id")
    @classmethod
    def validate_router_id(cls, value: IPv4Address) -> IPv4Address:
        if value.is_unspecified or value.is_multicast or value == IPv4Address("255.255.255.255"):
            raise ValueError("router_id must be a nonzero unicast IPv4 identifier")
        return value


class PeeringEndpoint(BaseModel):
    model_config = {"extra": "forbid"}

    router: str
    import_policy: PolicyName
    export_policy: PolicyName


class Peering(BaseModel):
    model_config = {"extra": "forbid"}

    subnet: str
    endpoints: list[PeeringEndpoint] = Field(min_length=2, max_length=2)


class HostGateway(BaseModel):
    model_config = {"extra": "forbid"}

    host: str
    subnet: str
    gateway: IPv4Address


class RoutingConfig(BaseModel):
    model_config = {"extra": "forbid"}

    routers: list[Router] = Field(min_length=1)
    peerings: list[Peering] = Field(default_factory=list)
    policies: list[RoutingPolicy] = Field(default_factory=list)
    host_gateways: list[HostGateway] = Field(default_factory=list)
    control_routes: list[IPv4Network] = Field(default_factory=list)

    def data_subnet_names(self, topology: NetworkTopology) -> set[str]:
        participants = {r.host for r in self.routers} | {g.host for g in self.host_gateways}
        return {i.subnet for h in topology.get_all_hosts() if h.name in participants
                for i in h.extra_interfaces}

    def validate_topology(self, topology: NetworkTopology) -> None:
        hosts = {h.name: h for h in topology.get_all_hosts()}
        subnets = {s.name: s for s in topology.get_all_subnets()}
        routers = {r.host: r for r in self.routers}
        policies = {p.name: p for p in self.policies}
        gateways = {g.host: g for g in self.host_gateways}
        if len(hosts) != len(topology.get_all_hosts()):
            raise ValueError("BGP host names must be unique")
        if len(routers) != len(self.routers):
            raise ValueError("routing router hosts must be unique")
        if len({r.asn for r in self.routers}) != len(self.routers):
            raise ValueError("only one router per AS is supported")
        if len({r.router_id for r in self.routers}) != len(self.routers):
            raise ValueError("router IDs must be unique")
        if len(policies) != len(self.policies):
            raise ValueError("routing policy names must be unique")
        if len(gateways) != len(self.host_gateways):
            raise ValueError("each end host must have exactly one routing gateway")
        participants = set(routers) | set(gateways)
        if not participants <= hosts.keys():
            raise ValueError(f"routing references unknown hosts: {sorted(participants - hosts.keys())}")
        for name in routers:
            if not hosts[name].extra_interfaces:
                raise ValueError(f"router {name!r} needs a data interface")
        networks = list(subnets.values())
        for i, subnet in enumerate(networks):
            for other in networks[i + 1:]:
                if subnet.cidr.overlaps(other.cidr):
                    raise ValueError(f"BGP subnet CIDRs overlap: {subnet.name!r}, {other.name!r}")

        addresses = set()
        for host in hosts.values():
            primary = topology.get_subnet_for_host(host)
            attachments = [(primary.name, host.ip_address)]
            attachments += [(i.subnet, i.ip_address) for i in host.extra_interfaces]
            if len({name for name, _ in attachments}) != len(attachments):
                raise ValueError(f"host {host.name!r} has repeated subnet attachments")
            if host.extra_interfaces and host.name not in participants:
                raise ValueError(f"host {host.name!r} needs routing configuration for its extra interfaces")
            for name, ip in attachments:
                if name not in subnets or ip is None:
                    raise ValueError(f"host {host.name!r} needs a known subnet and static interface IP")
                network = subnets[name].cidr
                if ip.is_multicast or ip.is_loopback or ip.is_unspecified:
                    raise ValueError(f"host {host.name!r} needs a unicast interface IP")
                if ip not in network or (network.prefixlen < 31 and ip in
                                          {network.network_address, network.broadcast_address}):
                    raise ValueError(f"host {host.name!r}: unusable interface IP {ip} in {name!r}")
                if ip in addresses:
                    raise ValueError(f"duplicate BGP interface IP {ip}")
                addresses.add(ip)

        data_names = self.data_subnet_names(topology)
        for connection in topology.subnet_connections:
            if (connection.from_subnet in data_names) != (connection.to_subnet in data_names):
                raise ValueError("subnet_connections cannot cross the control/data boundary")
        for name in data_names:
            subnet = subnets[name]
            if subnet.hosts or subnet.external or subnet.internet_egress:
                raise ValueError(f"data subnet {name!r} must have no primary hosts, external ingress, or internet egress")
        for prefix in self.control_routes:
            if prefix.prefixlen == 0 or any(prefix.overlaps(subnets[n].cidr) for n in data_names):
                raise ValueError("control_routes must not include a default or overlap data subnets")

        peering_names = set()
        for peering in self.peerings:
            names = {e.router for e in peering.endpoints}
            if len(names) != 2 or not names <= routers.keys():
                raise ValueError("a peering needs two distinct declared routers")
            if peering.subnet not in data_names or peering.subnet in peering_names:
                raise ValueError("peering subnets must be distinct data links")
            peering_names.add(peering.subnet)
            attached = {h.name for h in hosts.values()
                        if any(i.subnet == peering.subnet for i in h.extra_interfaces)}
            if attached != names:
                raise ValueError(f"peering {peering.subnet!r} must contain exactly its two router interfaces")
            for endpoint in peering.endpoints:
                if endpoint.import_policy not in policies or endpoint.export_policy not in policies:
                    raise ValueError("peering references an unknown routing policy")
                if any(r.local_preference is not None for r in policies[endpoint.export_policy].rules):
                    raise ValueError("local_preference may be attached only to imports")

        lan_names = data_names - peering_names
        for name in lan_names:
            attached_routers = [r.host for r in self.routers
                                if any(i.subnet == name for i in hosts[r.host].extra_interfaces)]
            if len(attached_routers) != 1:
                raise ValueError(f"data LAN {name!r} needs exactly one router")
        for gateway in self.host_gateways:
            host = hosts[gateway.host]
            if gateway.host in routers or len(host.extra_interfaces) != 1:
                raise ValueError("end hosts need exactly one data interface and cannot also be routers")
            if host.extra_interfaces[0].subnet != gateway.subnet or gateway.subnet not in lan_names:
                raise ValueError(f"gateway for {gateway.host!r} must use its data LAN")
            if not any(i.subnet == gateway.subnet and i.ip_address == gateway.gateway
                       for r in self.routers for i in hosts[r.host].extra_interfaces):
                raise ValueError(f"gateway {gateway.gateway} is not a router interface on the host LAN")
        for host in hosts.values():
            for interface in host.extra_interfaces:
                prefixes = interface.response_prefixes
                if not prefixes:
                    continue
                if host.name not in gateways:
                    raise ValueError("response_prefixes require an end-host data interface")
                if len(set(prefixes)) != len(prefixes):
                    raise ValueError("response_prefixes must be unique")
                if any(other.name not in routers and other.name != host.name
                       and any(i.subnet == interface.subnet for i in other.extra_interfaces)
                       for other in hosts.values()):
                    raise ValueError("response_prefixes require a dedicated end-host/router LAN")
                if any(not any(prefix.subnet_of(subnets[n].cidr)
                               for n in lan_names - {interface.subnet}) for prefix in prefixes):
                    raise ValueError("response_prefixes must be confined to another declared data LAN")
        for router in self.routers:
            connected = {subnets[i.subnet].cidr for i in hosts[router.host].extra_interfaces
                         if i.subnet in lan_names}
            if len(set(router.advertised_prefixes)) != len(router.advertised_prefixes):
                raise ValueError("advertised_prefixes must be unique")
            if not set(router.advertised_prefixes) <= connected:
                raise ValueError("initial advertised prefixes must be connected router LANs")
        lans = [subnets[n].cidr for n in lan_names]
        for policy in self.policies:
            for rule in policy.rules:
                if rule.action == "permit" and not any(rule.prefix.subnet_of(n) for n in lans):
                    raise ValueError("permit rules must be confined to declared data LAN prefixes")
