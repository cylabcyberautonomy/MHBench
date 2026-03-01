"""
OpenStack Attacker Network Deployer

This module provides functionality to deploy attacker network infrastructure on OpenStack.
It creates an attacker network, attaches it to the router, creates security groups for
full network access, and deploys a Kali Linux attacker host for penetration testing.
"""

import logging
from typing import Any, cast

import openstack.connection
from src.openstack.imager import get_image_name


class OpenstackAttackerNetworkDeployer:
    """Deploys attacker network infrastructure to OpenStack."""

    def __init__(
        self,
        connection: openstack.connection.Connection,
        router_name: str,
        attacker_ssh_key_name: str,
        project_name: str = "perry",
    ):
        """
        Initialize the OpenStack attacker network deployer.

        Args:
            connection: OpenStack connection object
            router_name: Name of the router to attach to
            attacker_ssh_key_name: Name of the SSH key for the attacker host
            project_name: Name of the OpenStack project/tenant
        """
        self.conn = connection
        self.project_name = project_name
        self.logger = logging.getLogger(__name__)

        # OpenStack typing is not great, so we need to cast services to Any
        self.network_service = cast(Any, connection.network)
        self.compute_service = cast(Any, connection.compute)

        # Attacker network configuration
        self.external_network_name = "external"
        self.attacker_network_name = "attacker_network"
        self.attacker_subnet_name = "attacker"
        self.attacker_cidr = "192.168.199.0/24"
        self.attacker_host_ip = "192.168.199.14"
        self.attacker_host_name = "attacker_host"
        self.attacker_host_image_name = "kali-cloud"
        self.attacker_host_flavor_name = "m1.small"

        self.attacker_freedom_sg_name = "attacker_freedom"

        self.attacker_ssh_key_name = attacker_ssh_key_name
        self.router_name = router_name

    def deploy_attacker_infrastructure(self, use_base_image=True):
        """
        Deploy complete attacker infrastructure including network, security groups, and host.

        Returns:
            Dictionary containing deployed resource information
        """
        self.logger.info("Starting deployment of attacker infrastructure")

        # 1. Create security groups
        self._create_attacker_security_groups()

        # 2. Create attacker network
        network, subnet = self._create_attacker_network()

        # 3. Attach to router
        self._attach_to_router(subnet)

        # 4. Create attacker host
        self._create_attacker_host(network, use_base_image)

        self.logger.info("Attacker infrastructure deployment completed successfully")

    def _create_attacker_security_groups(self):
        """Create security groups for attacker network access."""
        self.logger.info("Creating attacker security groups")

        """Create security group for full network access from attacker host."""
        sg_name = self.attacker_freedom_sg_name

        # Check if security group already exists
        existing_sg = self.network_service.find_security_group(sg_name)
        if existing_sg:
            raise Exception(f"Security group {sg_name} already exists")

        # Create security group
        sg = self.network_service.create_security_group(
            name=sg_name,
            description="Security group for full network access from attacker host",
        )

        # Allow all TCP ingress from anywhere
        self.network_service.create_security_group_rule(
            security_group_id=sg.id,
            direction="ingress",
            protocol="tcp",
            port_range_min=1,
            port_range_max=65535,
            remote_ip_prefix="0.0.0.0/0",
        )

        # Allow all TCP egress to anywhere
        self.network_service.create_security_group_rule(
            security_group_id=sg.id,
            direction="egress",
            protocol="tcp",
            port_range_min=1,
            port_range_max=65535,
            remote_ip_prefix="0.0.0.0/0",
        )

        # Allow all UDP ingress from anywhere
        self.network_service.create_security_group_rule(
            security_group_id=sg.id,
            direction="ingress",
            protocol="udp",
            port_range_min=1,
            port_range_max=65535,
            remote_ip_prefix="0.0.0.0/0",
        )

        # Allow all UDP egress to anywhere
        self.network_service.create_security_group_rule(
            security_group_id=sg.id,
            direction="egress",
            protocol="udp",
            port_range_min=1,
            port_range_max=65535,
            remote_ip_prefix="0.0.0.0/0",
        )

        # Allow all ICMP ingress from anywhere
        self.network_service.create_security_group_rule(
            security_group_id=sg.id,
            direction="ingress",
            protocol="icmp",
            remote_ip_prefix="0.0.0.0/0",
        )

        # Allow all ICMP egress to anywhere
        self.network_service.create_security_group_rule(
            security_group_id=sg.id,
            direction="egress",
            protocol="icmp",
            remote_ip_prefix="0.0.0.0/0",
        )

        self.logger.info(f"Created security group: {sg_name}")
        return sg

    def _create_attacker_network(self):
        """Create attacker network and subnet."""
        self.logger.info("Creating attacker network")

        # Check if network already exists
        existing_network = self.network_service.find_network(self.attacker_network_name)
        if existing_network:
            raise Exception(f"Network {self.attacker_network_name} already exists")

        # Create network
        network = self.network_service.create_network(
            name=self.attacker_network_name,
            admin_state_up=True,
            description="Attacker network for penetration testing",
        )

        # Create subnet
        subnet = self.network_service.create_subnet(
            name=self.attacker_subnet_name,
            network_id=network.id,
            ip_version=4,
            cidr=self.attacker_cidr,
            enable_dhcp=True,
            dns_nameservers=["8.8.8.8"],
        )

        self.logger.info(
            f"Created attacker network: {self.attacker_network_name} with subnet CIDR: {self.attacker_cidr}"
        )
        return network, subnet

    def _attach_to_router(self, subnet):
        """Attach attacker subnet to router."""
        self.logger.info("Attaching attacker network to router")

        router = self.network_service.find_router(self.router_name)
        if not router:
            raise Exception(f"Router {self.router_name} not found")

        # Add router interface
        self.network_service.add_interface_to_router(
            router=router.id, subnet_id=subnet.id
        )

        self.logger.info(f"Attached attacker subnet to router: {router.name}")

    def _create_attacker_host(self, network, use_base_image=True):
        """Create attacker host (Kali Linux) with floating IP."""
        self.logger.info("Creating attacker host")

        # Check if host already exists
        existing_instance = self.compute_service.find_server(self.attacker_host_name)
        if existing_instance:
            raise Exception(f"Attacker host {self.attacker_host_name} already exists")

        # Get image for Kali Linux
        if use_base_image:
            image = self.compute_service.find_image(self.attacker_host_image_name)
            print(f"Found image: {image.name}")
        else:
            image_name = get_image_name(self.attacker_host_name)
            image = self.compute_service.find_image(image_name)
            print(f"Found image 2: {image.name}")
        if not image:
            raise Exception(f"{self.attacker_host_image_name} image not found")

        # Get flavor (use m1.small or equivalent)
        flavor = self.compute_service.find_flavor(self.attacker_host_flavor_name)
        if not flavor:
            raise Exception(f"{self.attacker_host_flavor_name} flavor not found")

        # Create instance
        instance = self.compute_service.create_server(
            name=self.attacker_host_name,
            imageRef=image.id,
            flavorRef=flavor.id,
            networks=[{"uuid": network.id, "fixed_ip": self.attacker_host_ip}],
            security_groups=[
                {"name": self.attacker_freedom_sg_name},
            ],
            metadata={"role": "attacker", "type": "kali"},
            key_name=self.attacker_ssh_key_name,
        )

        # Wait for instance to become active
        instance = self.compute_service.wait_for_server(instance)
        self.logger.info(f"Created attacker host: {self.attacker_host_name}")

        return instance
