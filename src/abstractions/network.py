from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

from pydantic import BaseModel, Field, computed_field


class SubnetConnection(BaseModel):
    from_subnet: str
    to_subnet: str
    protocol: str | None = None
    ports: list[int] | None = None
    bidirectional: bool = True


class PlaybookRef(BaseModel):
    name: str
    args: dict = Field(default_factory=dict)


class HostInterface(BaseModel):
    subnet: str
    ip_address: IPv4Address | None = None


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

    def get_all_hosts(self) -> list[Host]:
        return [h for net in self.networks for sub in net.subnets for h in sub.hosts]

    def get_all_subnets(self) -> list[Subnet]:
        return [sub for net in self.networks for sub in net.subnets]

    def get_subnet_by_name(self, name: str) -> Subnet | None:
        return next((s for s in self.get_all_subnets() if s.name == name), None)

    def get_subnet_for_host(self, host: Host) -> Subnet | None:
        return next((s for s in self.get_all_subnets() if host in s.hosts), None)
