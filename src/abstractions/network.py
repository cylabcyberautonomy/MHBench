from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
from typing import Annotated

from pydantic import BaseModel, Field, computed_field, field_validator, model_validator

from src.abstractions.routing import RoutingConfig


class SubnetConnection(BaseModel):
    from_subnet: str
    to_subnet: str
    protocol: str | None = None
    ports: list[Annotated[int, Field(ge=1, le=65535, strict=True)]] | None = None
    bidirectional: bool = True

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.lower()
        if value.isdecimal():
            value = str(int(value))
        aliases = {"all": None, "1": "icmp", "6": "tcp", "17": "udp", "132": "sctp", "gre": "47"}
        if value in aliases:
            return aliases[value]
        if value in {"tcp", "udp", "icmp", "esp", "ah", "ipip", "sctp"}:
            return value
        if value.isdecimal() and 1 <= int(value) <= 255:
            return str(int(value))
        raise ValueError("protocol must be an IP protocol name or number (1-255), or null")

    @model_validator(mode="after")
    def validate_ports(self) -> SubnetConnection:
        if self.ports is not None:
            if not self.ports:
                raise ValueError("ports must be a nonempty list or null")
            if self.protocol not in {"tcp", "udp", "sctp"}:
                raise ValueError("ports require protocol tcp, udp, or sctp")
        return self


class PlaybookRef(BaseModel):
    name: str
    args: dict = Field(default_factory=dict)


class HostInterface(BaseModel):
    subnet: str
    ip_address: IPv4Address | None = None
    response_prefixes: list[IPv4Network] = Field(default_factory=list)


class Host(BaseModel):
    name: str
    vm_type: str
    flavor: str = "m1.small"
    ip_address: IPv4Address | None = None
    extra_interfaces: list[HostInterface] = Field(default_factory=list)


class Subnet(BaseModel):
    name: str
    cidr: IPv4Network
    dns_servers: list[str] = Field(default_factory=lambda: ["8.8.8.8"])
    hosts: list[Host] = Field(default_factory=list)
    external: bool = False
    internet_egress: bool = True
    # Declarative marker: the internet-facing / perimeter tier (e.g. the DMZ webserver segment an
    # external attacker reaches first). PURELY informational — unlike `external` it drives NO provisioning
    # (no public gateway, no 0.0.0.0/0 SG rule); it just lets a consumer (the arena's defender spec) know
    # which segment is the perimeter so deception can bait the ingress path from a property the defender
    # legitimately owns, rather than inferring the attacker's position from subnet_connections.
    perimeter: bool = False

    @computed_field
    @property
    def sg_name(self) -> str:
        return f"{self.name}_sg"


class Network(BaseModel):
    name: str
    description: str = ""
    subnets: list[Subnet] = Field(default_factory=list)


class NetworkTopology(BaseModel):
    name: str
    networks: list[Network] = Field(default_factory=list)
    subnet_connections: list[SubnetConnection] = Field(default_factory=list)
    playbooks: list[PlaybookRef] = Field(default_factory=list)
    routing: RoutingConfig | None = None

    @model_validator(mode="after")
    def validate_connections(self) -> NetworkTopology:
        names = [s.name for s in self.get_all_subnets()]
        if len(names) != len(set(names)):
            raise ValueError("subnet names must be unique")
        for connection in self.subnet_connections:
            for name in (connection.from_subnet, connection.to_subnet):
                if name not in names:
                    raise ValueError(f"Connection references unknown subnet {name!r}")
        if self.routing is not None:
            self.routing.validate_topology(self)
        elif any(i.response_prefixes for h in self.get_all_hosts() for i in h.extra_interfaces):
            raise ValueError("response_prefixes require routing")
        return self

    def get_ingress_connections(self, subnet_name: str) -> list[SubnetConnection]:
        """Incoming initiation permissions, with explicit pairs overriding role defaults."""
        incoming = []
        explicit_peers = set()
        for connection in self.subnet_connections:
            if connection.to_subnet == subnet_name:
                explicit_peers.add(connection.from_subnet)
                incoming.append(connection)
            elif connection.from_subnet == subnet_name:
                explicit_peers.add(connection.to_subnet)
                if connection.bidirectional:
                    incoming.append(connection.model_copy(update={
                        "from_subnet": connection.to_subnet, "to_subnet": subnet_name,
                        "bidirectional": False,
                    }))
        data_names = self.routing.data_subnet_names(self) if self.routing is not None else set()
        for source in self.get_all_subnets():
            if subnet_name in data_names or source.name in data_names:
                continue
            if source.name == subnet_name or source.name in explicit_peers:
                continue
            callback = (subnet_name == "attacker_subnet" and not source.external
                        and source.name != "defender_subnet")
            response = (source.name == "defender_subnet"
                        and subnet_name not in {"attacker_subnet", "defender_subnet"})
            if callback or response:
                incoming.append(SubnetConnection(
                    from_subnet=source.name, to_subnet=subnet_name, bidirectional=False,
                ))
        return incoming

    def get_all_hosts(self) -> list[Host]:
        return [h for net in self.networks for sub in net.subnets for h in sub.hosts]

    def get_all_subnets(self) -> list[Subnet]:
        return [sub for net in self.networks for sub in net.subnets]

    def get_subnet_by_name(self, name: str) -> Subnet | None:
        return next((s for s in self.get_all_subnets() if s.name == name), None)

    def get_subnet_for_host(self, host: Host) -> Subnet | None:
        return next((s for s in self.get_all_subnets() if host in s.hosts), None)

    def get_host_by_name(self, name: str) -> Host | None:
        return next((h for h in self.get_all_hosts() if h.name == name), None)
