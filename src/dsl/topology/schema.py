"""
Pydantic models for the MHBench Topology DSL (YANG instance data in YAML).

These models mirror the mhbench-network YANG module and validate topology
YAML files before compilation into a NetworkTopology.

Topology YAML shape:

    name: equifax_small
    description: "Equifax breach simulation — 6 hosts"
    networks:
      - name: webserver_network
        subnets:
          - name: webserver_subnet
            cidr: "192.168.200.0/24"
            external: true          # allows 0.0.0.0/0 ingress/egress
            host_groups:
              - vm_type: webserver  # resolved via VmTypeRegistry
                count: 2
                ip_start: "192.168.200.10"
    subnet_connections:
      - from_subnet: webserver_subnet
        to_subnet: corporate_subnet
        bidirectional: true
    attacker:
      vm_type: kali_attacker

YANG reference: src/dsl/topology/mhbench_network.yang
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, field_validator

from src.models.enums import ProtocolType


class HostGroupSpec(BaseModel):
    """
    Declares N hosts of a named VM type within a subnet.

    The compiler expands this into individual Host objects, assigning
    sequential IPs starting at ip_start (if provided).

    YANG: /network-topology/network/subnet/host-group
    """

    vm_type: str
    count: int
    # Name prefix for generated hosts, e.g. "webserver" → webserver_0, webserver_1.
    # Defaults to vm_type when absent.
    name_prefix: Optional[str] = None
    # First IP to assign; subsequent hosts increment by 1.
    # When absent, IP assignment is left to OpenStack DHCP.
    ip_start: Optional[str] = None

    @field_validator("count")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("count must be >= 1")
        return v


class SubnetSpec(BaseModel):
    """
    YANG: /network-topology/network/subnet
    """

    name: str
    cidr: str
    dns_servers: List[str] = ["8.8.8.8"]
    # True → security group allows TCP ingress and egress from 0.0.0.0/0.
    external: bool = False
    gateway_ip: Optional[str] = None
    host_groups: List[HostGroupSpec] = []


class NetworkSpec(BaseModel):
    """
    YANG: /network-topology/network
    """

    name: str
    description: str = ""
    subnets: List[SubnetSpec] = []
    is_external: bool = False


class SubnetConnectionSpec(BaseModel):
    """
    Declares allowed traffic between two subnets.

    protocol=None  → all protocols permitted (maps to SubnetConnection.protocol=None)
    ports=None     → all ports permitted     (maps to SubnetConnection.ports=None)

    YANG: /network-topology/subnet-connection
    """

    from_subnet: str
    to_subnet: str
    bidirectional: bool = True
    protocol: Optional[ProtocolType] = None
    ports: Optional[List[int]] = None


class AttackerSpec(BaseModel):
    """
    Declares the red-team host.

    Not placed in any named network — EnvGenDeployer puts it on the dedicated
    attacker network (192.168.202.0/24 by convention).

    YANG: /network-topology/attacker-host
    """

    vm_type: str


class TopologySpec(BaseModel):
    """
    Root of a topology YAML file.

    YANG: /network-topology
    """

    name: str
    description: str = ""
    networks: List[NetworkSpec] = []
    subnet_connections: List[SubnetConnectionSpec] = []
    attacker: Optional[AttackerSpec] = None

    @classmethod
    def from_yaml(cls, path: str) -> "TopologySpec":
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)
