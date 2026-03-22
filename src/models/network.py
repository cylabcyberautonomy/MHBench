"""
Network topology models for cyberrange specifications.

This module contains models for defining network topologies including
hosts, subnets, networks, and security configurations.
"""

from typing import List, Optional, Set
from pydantic import BaseModel, Field, model_validator, computed_field
from ipaddress import IPv4Network, IPv4Address
from uuid import UUID, uuid4

from .enums import OSType, FlavorType, ProtocolType
from .components import User, create_default_root_user
from .goals import GoalUnion
from .vulnerabilities import Vulnerability
from src.models.attack_paths import AttackPath
from .attack_graph import AttackGraph


class SubnetConnection(BaseModel):
    """Represents a connection between two subnets."""

    from_subnet: str
    to_subnet: str
    protocol: Optional[ProtocolType] = None  # if None, all protocols allowed
    ports: Optional[List[int]] = None  # if None, all ports allowed
    bidirectional: bool = True  # if True, connection works both ways

    def allows_traffic(self, protocol: ProtocolType, port: int) -> bool:
        """Check if this connection allows specific traffic."""
        if self.protocol is not None and self.protocol != protocol:
            return False
        if self.ports is not None and port not in self.ports:
            return False
        return True


class Host(BaseModel):
    """Host/instance specification."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    os_type: OSType
    flavor: FlavorType = FlavorType.TINY
    ip_address: Optional[IPv4Address] = None
    image_name: Optional[str] = None  # Overrides os_type→image lookup when set
    users: List[User] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)

    is_attacker: bool = False
    is_decoy: bool = False

    @model_validator(mode="after")
    def _ensure_root_user(self):
        """Ensure every host has a 'root' user."""
        root_user_exists = any(user.username == "root" for user in self.users)
        if not root_user_exists:
            # Add a default root user
            root_user = create_default_root_user()
            self.users.append(root_user)
        return self

    def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        """Find a user by UUID."""
        for user in self.users:
            if user.id == user_id:
                return user
        return None

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Find a user by username."""
        for user in self.users:
            if user.username == username:
                return user
        return None

    def get_root_user(self) -> User:
        """Get the root user for the host."""
        root_user = self.get_user_by_username("root")
        if root_user is None:
            raise Exception("Root user not found")
        return root_user


class Subnet(BaseModel):
    """Subnet specification."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    cidr: IPv4Network
    dns_servers: List[str] = ["8.8.8.8"]
    hosts: List[Host] = Field(default_factory=list)
    gateway_ip: Optional[IPv4Address] = None
    external: bool = False

    @computed_field
    @property
    def sg_name(self) -> str:
        """Security group name based on subnet name."""
        return f"{self.name}_sg"


class Network(BaseModel):
    """Network specification."""

    name: str
    description: str = ""
    subnets: List[Subnet] = Field(default_factory=list)
    is_external: bool = False


class NetworkTopology(BaseModel):
    """Complete network topology specification."""

    name: str
    networks: List[Network] = Field(default_factory=list)
    subnet_connections: List[SubnetConnection] = Field(default_factory=list)
    goals: List[GoalUnion] = Field(default_factory=list)
    attack_paths: List[AttackPath] = Field(default_factory=list)
    attack_graph: Optional[AttackGraph] = None
    attacker_host: Optional[Host] = None

    def get_all_hosts(self, include_attacker: bool = False) -> List[Host]:
        """Get all hosts across all networks."""
        hosts = []
        for network in self.networks:
            for subnet in network.subnets:
                hosts.extend(subnet.hosts)

        if include_attacker and self.attacker_host:
            hosts.append(self.attacker_host)

        return hosts

    def get_host_by_name(self, name: str) -> Optional[Host]:
        """Find a host by name."""
        for host in self.get_all_hosts():
            if host.name == name:
                return host
        return None

    def get_host_by_id(
        self, host_id: UUID, include_attacker: bool = False
    ) -> Optional[Host]:
        """Find a host by UUID."""
        for host in self.get_all_hosts(include_attacker=include_attacker):
            if host.id == host_id:
                return host
        return None

    def get_host_by_user(self, user: User) -> Optional[Host]:
        """Find a host by user."""
        for host in self.get_all_hosts():
            host_user_ids = [user.id for user in host.users]
            if user.id in host_user_ids:
                return host
        return None

    def get_user_by_id(
        self, user_id: UUID, include_attacker: bool = False
    ) -> Optional[User]:
        """Find a user by UUID."""
        for host in self.get_all_hosts(include_attacker=include_attacker):
            for user in host.users:
                if user.id == user_id:
                    return user
        return None

    def get_all_subnets(self) -> List[Subnet]:
        """Get all subnets across all networks."""
        subnets = []
        for network in self.networks:
            subnets.extend(network.subnets)
        return subnets

    def get_subnet_by_name(self, name: str) -> Optional[Subnet]:
        """Find a subnet by name."""
        for subnet in self.get_all_subnets():
            if subnet.name == name:
                return subnet
        return None

    def get_subnet_by_id(self, subnet_id: UUID) -> Optional[Subnet]:
        """Find a subnet by UUID."""
        for subnet in self.get_all_subnets():
            if subnet.id == subnet_id:
                return subnet
        return None

    def get_subnet_for_host(self, host: Host) -> Optional[Subnet]:
        """Find the subnet containing a specific host."""
        for subnet in self.get_all_subnets():
            if host in subnet.hosts:
                return subnet
        return None

    def can_subnets_communicate(
        self,
        from_subnet: str,
        to_subnet: str,
        protocol: Optional[ProtocolType] = None,
        port: Optional[int] = None,
    ) -> bool:
        """
        Check if two subnets can communicate based on subnet connections.

        Args:
            from_subnet: Name of the source subnet
            to_subnet: Name of the destination subnet
            protocol: Optional protocol to check
            port: Optional port to check

        Returns:
            True if communication is allowed, False otherwise
        """
        if from_subnet == to_subnet:
            return True  # Same subnet can always communicate internally

        # Check direct connections
        for conn in self.subnet_connections:
            if conn.from_subnet == from_subnet and conn.to_subnet == to_subnet:
                if protocol is not None and port is not None:
                    return conn.allows_traffic(protocol, port)
                return True
            # Check bidirectional connections
            if (
                conn.bidirectional
                and conn.from_subnet == to_subnet
                and conn.to_subnet == from_subnet
            ):
                if protocol is not None and port is not None:
                    return conn.allows_traffic(protocol, port)
                return True

        return False

    def find_subnet_path(self, from_subnet: str, to_subnet: str) -> Optional[List[str]]:
        """
        Find a path between two subnets using routing rules and connections.

        Args:
            from_subnet: Name of the source subnet
            to_subnet: Name of the destination subnet

        Returns:
            List of subnet names representing the path, or None if no path exists
        """
        if from_subnet == to_subnet:
            return [from_subnet]

        # Simple BFS to find shortest path
        from collections import deque

        queue = deque([(from_subnet, [from_subnet])])
        visited = {from_subnet}

        while queue:
            current_subnet, path = queue.popleft()

            # Check all possible next hops
            for conn in self.subnet_connections:
                next_subnet = None

                if conn.from_subnet == current_subnet:
                    next_subnet = conn.to_subnet
                elif conn.bidirectional and conn.to_subnet == current_subnet:
                    next_subnet = conn.from_subnet

                if next_subnet and next_subnet not in visited:
                    new_path = path + [next_subnet]

                    if next_subnet == to_subnet:
                        return new_path

                    visited.add(next_subnet)
                    queue.append((next_subnet, new_path))

        return None  # No path found

    def get_connected_subnets(self, subnet_name: str) -> Set[str]:
        """
        Get all subnets that are directly connected to the given subnet.

        Args:
            subnet_name: Name of the subnet

        Returns:
            Set of subnet names that are directly connected
        """
        connected = set()

        for conn in self.subnet_connections:
            if conn.from_subnet == subnet_name:
                connected.add(conn.to_subnet)
            elif conn.bidirectional and conn.to_subnet == subnet_name:
                connected.add(conn.from_subnet)

        return connected

    def validate_subnet_connectivity(self) -> List[str]:
        """
        Validate subnet connectivity configuration and return any issues.

        Returns:
            List of validation error messages
        """
        errors = []
        all_subnet_names = {subnet.name for subnet in self.get_all_subnets()}

        # Check that all referenced subnets exist
        for conn in self.subnet_connections:
            if conn.from_subnet not in all_subnet_names:
                errors.append(
                    f"Subnet connection references unknown subnet: {conn.from_subnet}"
                )
            if conn.to_subnet not in all_subnet_names:
                errors.append(
                    f"Subnet connection references unknown subnet: {conn.to_subnet}"
                )

        return errors

    def apply_vulnerabilities(self) -> None:
        """Apply vulnerabilities from attack graph to the network."""
        if self.attack_graph is None:
            raise Exception("Attack graph is not set")
        for edge in self.attack_graph.get_all_edges():
            if edge.vulnerability is None:
                raise Exception("Vulnerability is not set for edge")

            ag_node = self.attack_graph.get_node_by_id(edge.to_node_id)
            if ag_node is None:
                raise Exception(f"AttackGraphNode {edge.to_node_id} not found")

            to_host = self.get_host_by_id(ag_node.host_id)

            if to_host is None:
                raise Exception(f"Host not found for AttackGraphNode {edge.to_node_id}")
            to_host.vulnerabilities.append(edge.vulnerability)

    @model_validator(mode="after")
    def _validate_topology(self):
        """Validate that all attack paths reference valid hosts and subnet connectivity is valid."""
        # Validate attack paths
        all_host_ids = {h.id for h in self.get_all_hosts()}
        if self.attacker_host is not None:
            all_host_ids.add(self.attacker_host.id)

        for path in self.attack_paths:
            missing = set(path.get_all_host_ids()) - all_host_ids
            if missing:
                raise Exception(
                    f"AttackPath {path.id} references unknown host ids {missing}"
                )

            # Validate path continuity
            if not path.validate_path_continuity():
                raise Exception(f"AttackPath {path.id} has discontinuous steps")

        # Validate subnet connectivity
        connectivity_errors = self.validate_subnet_connectivity()
        if connectivity_errors:
            raise Exception(
                f"Subnet connectivity validation failed: {'; '.join(connectivity_errors)}"
            )

        return self
