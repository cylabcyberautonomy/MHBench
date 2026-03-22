#!/usr/bin/env python3
"""
Simple Network Generator

A basic network generator that creates networks with random numbers of subnets
using the Perry DSL from the environment.models package.
"""

import os
import random
from typing import List
from ipaddress import IPv4Network

from src.models import (
    NetworkTopology,
    Network,
    Subnet,
    SubnetConnection,
    Host,
    OSType,
    FlavorType,
    User,
    JSONDataExfiltrationGoal,
    Goal,
)
from .attack_path_generator import AttackPathGenerator
from src.topology_generator.vulnerability_assignment import VulnerabilityAssigner
from src.models.virtual_attacker import create_default_external_attacker
from src.models.attack_graph import (
    build_attack_graph,
    prune_edges_by_host,
    validate_attack_graph,
)


class SimpleNetworkGenerator:
    """A simple network generator that creates networks with random subnets."""

    def __init__(
        self,
        min_subnets: int = 1,
        max_subnets: int = 4,
        min_hosts_per_subnet: int = 1,
        max_hosts_per_subnet: int = 5,
        seed: int | None = None,
        subnet_connections_probability: float = 0.3,
        goal_host_probability: float = 0.1,
    ):
        """Initialize the generator with an optional random seed."""
        self.min_subnets = min_subnets
        self.max_subnets = max_subnets

        self.min_hosts_per_subnet = min_hosts_per_subnet
        self.max_hosts_per_subnet = max_hosts_per_subnet

        self.goal_host_probability = goal_host_probability

        self.subnet_connections_probability = subnet_connections_probability

        if seed is not None:
            random.seed(seed)

    def generate_network(
        self, network_name: str = "generated_network"
    ) -> NetworkTopology:
        """Generate a network with a random number of subnets."""
        # Generate random number of subnets (1-4)
        num_subnets = random.randint(self.min_subnets, self.max_subnets)
        subnets = [self._generate_random_subnet(i) for i in range(num_subnets)]

        # First subnet is external
        external_subnet = subnets[0]
        external_subnet.external = True

        # Randomly add hosts to subnets
        for subnet in subnets:
            num_hosts = random.randint(
                self.min_hosts_per_subnet, self.max_hosts_per_subnet
            )
            subnet.hosts = [
                self._generate_random_host(subnet, host_num)
                for host_num in range(num_hosts)
            ]

        # Randomly create connections between subnets
        connections = self._generate_random_connections(subnets)

        # Create network
        network = Network(
            name=network_name,
            description=f"Generated network with {num_subnets} subnets",
            subnets=subnets,
        )

        # Create topology
        topology = NetworkTopology(
            name=f"{network_name}_topology",
            networks=[network],
            subnet_connections=connections,
        )

        # Generate goals
        goals = self._generate_goals(topology)
        topology.goals = goals

        # Create virtual attacker host
        topology.attacker_host = create_default_external_attacker()

        # Generate attack paths from an external subnet to each goal
        attack_paths = AttackPathGenerator().generate_paths_for_topology(topology)
        topology.attack_paths = attack_paths

        # Step 2: assign vulnerabilities for each step and prune duplicates
        VulnerabilityAssigner().assign_for_topology(topology)

        # Build attack graph
        attack_graph = build_attack_graph(attack_paths)
        attack_graph = prune_edges_by_host(attack_graph)
        validate_attack_graph(attack_graph, goals)

        topology.attack_graph = attack_graph
        topology.apply_vulnerabilities()

        # installations = compute_installations(attack_graph)
        # apply_installations_to_topology(installations, topology)

        NetworkTopology.model_validate(topology, strict=True)

        return topology

    def _generate_random_subnet(self, subnet_num: int) -> Subnet:
        """Generate a subnet with a random number of hosts."""
        # Generate subnet CIDR (using 192.168.x.0/24 pattern)
        subnet_third_octet = 200 + subnet_num
        subnet_cidr = IPv4Network(f"192.168.{subnet_third_octet}.0/24")

        return Subnet(
            name=f"subnet_{subnet_num}",
            cidr=subnet_cidr,
            hosts=[],
        )

    def _generate_random_host(self, subnet: Subnet, host_num: int) -> Host:
        """Generate a random host."""

        # Generate an IP address for the host
        host_ip = subnet.cidr.network_address + host_num + 10

        # Create a user for the host
        user = User(
            username=f"user_{host_num}",
            home_directory=f"/home/user_{host_num}",
        )

        return Host(
            name=f"host_{host_num}_{subnet.name}",
            os_type=OSType.UBUNTU_20,
            flavor=FlavorType.TINY,
            ip_address=host_ip,
            image_name="mhbench_ubuntu_baked",
            users=[user],
        )

    def _generate_goals(self, topology: NetworkTopology) -> List[Goal]:
        """Generate goals for the network."""
        goals = []
        all_hosts = topology.get_all_hosts()

        # Generate goals probabilistically
        for host in all_hosts:
            # Get subnets for the host
            subnet = topology.get_subnet_for_host(host)
            if not subnet:
                continue

            if subnet.external:
                continue

            if random.random() < self.goal_host_probability:
                target_user = random.choice(host.users)
                goals.append(
                    JSONDataExfiltrationGoal(
                        target_host_id=host.id,
                        target_user_id=target_user.id,
                        host_ip=str(host.ip_address),
                        dst_path=os.path.join(
                            target_user.home_directory, f"data_{host.name}.json"
                        ),
                        host_user=target_user.username,
                    )
                )

        # Guarantee at least one host has a goal
        if not goals and all_hosts:
            # Choose a random host to ensure at least one goal exists
            random_host = random.choice(all_hosts)
            target_user = random.choice(random_host.users)
            goals.append(
                JSONDataExfiltrationGoal(
                    target_host_id=random_host.id,
                    target_user_id=target_user.id,
                    host_ip=str(random_host.ip_address),
                    dst_path=os.path.join(
                        target_user.home_directory, f"data_{random_host.name}.json"
                    ),
                    host_user=target_user.username,
                )
            )

        return goals

    def _generate_random_connections(
        self, subnets: List[Subnet]
    ) -> List[SubnetConnection]:
        """Generate random connections between subnets."""
        if len(subnets) <= 1:
            return []

        connections = []
        subnet_names = [subnet.name for subnet in subnets]

        # First, ensure connectivity by creating a minimum spanning tree
        # Start with first subnet and randomly connect others to ensure connectivity
        connected_subnets = {subnet_names[0]}
        unconnected_subnets = set(subnet_names[1:])

        while unconnected_subnets:
            # Pick a random connected subnet and a random unconnected subnet
            from_subnet = random.choice(list(connected_subnets))
            to_subnet = random.choice(list(unconnected_subnets))

            # Create bidirectional connection
            connections.append(
                SubnetConnection(
                    from_subnet=from_subnet, to_subnet=to_subnet, bidirectional=True
                )
            )

            # Move subnet to connected set
            connected_subnets.add(to_subnet)
            unconnected_subnets.remove(to_subnet)

        # Add additional random connections with 30% probability for each possible pair
        connection_probability = self.subnet_connections_probability
        existing_pairs = set()

        # Track existing connections to avoid duplicates
        for conn in connections:
            existing_pairs.add((conn.from_subnet, conn.to_subnet))
            existing_pairs.add((conn.to_subnet, conn.from_subnet))  # bidirectional

        # Consider all possible subnet pairs for additional connections
        for i, subnet1 in enumerate(subnet_names):
            for subnet2 in subnet_names[i + 1 :]:  # Only consider each pair once
                if (subnet1, subnet2) not in existing_pairs:
                    if random.random() < connection_probability:
                        connections.append(
                            SubnetConnection(
                                from_subnet=subnet1,
                                to_subnet=subnet2,
                                bidirectional=True,
                            )
                        )

        return connections


def main():
    """Main function to demonstrate the generator."""

    # Create generator
    generator = SimpleNetworkGenerator(
        min_subnets=2,
        max_subnets=4,
        goal_host_probability=0.3,
        min_hosts_per_subnet=7,
        max_hosts_per_subnet=15,
    )

    # Generate 10 networks
    for i in range(13, 30):
        # Generate a network
        topology = generator.generate_network(f"demo_network_{i}")

        # Save to JSON file
        output_file = f"environment/models/examples/generated_network_{i}.json"
        with open(output_file, "w") as f:
            f.write(topology.model_dump_json(indent=2, serialize_as_any=True))


if __name__ == "__main__":
    main()
