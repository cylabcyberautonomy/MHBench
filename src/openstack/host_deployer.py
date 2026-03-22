"""
OpenStack Host Deployer

This module provides functionality to deploy hosts from Perry topology specifications
to OpenStack infrastructure. It creates compute instances based on the host definitions
in the network topology.
"""

import logging
import time
from typing import Dict, List, Any, cast, Optional, Tuple

import openstack.connection

from src.models import NetworkTopology, Host
from src.models.enums import OSType, FlavorType
from src.openstack.imager import get_image_name


class OpenstackHostDeployer:
    """Deploys hosts from topology specifications to OpenStack infrastructure."""

    def __init__(
        self,
        connection: openstack.connection.Connection,
        manage_ssh_key_name: str,
        talk_to_manage_sg_name: str,
        topology: NetworkTopology,
        project_name: str = "perry",
    ):
        """
        Initialize the OpenStack host deployer.

        Args:
            connection: OpenStack connection object
            project_name: Name of the OpenStack project/tenant
        """
        self.conn = connection
        self.project_name = project_name
        self.manage_ssh_key_name = manage_ssh_key_name
        self.logger = logging.getLogger(__name__)
        self.topology = topology

        # OpenStack typing is not great, so we need to cast services to Any
        self.compute_service = cast(Any, connection.compute)
        self.network_service = cast(Any, connection.network)

        # Track created resources for cleanup
        self.created_instances: Dict[str, Any] = {}

        # Fallback OS→image mapping for hosts without image_name set.
        self.os_image_mapping: Dict[OSType, str] = {
            OSType.UBUNTU_20: "Ubuntu20",
            OSType.KALI_LINUX: "kali-cloud",
        }

        # Flavor mapping - these should match your OpenStack environment
        self.flavor_mapping = {
            FlavorType.TINY: "p2.tiny",
            FlavorType.SMALL: "p2.small",
            FlavorType.MEDIUM: "p2.medium",
            FlavorType.LARGE: "p2.large",
        }

        self.talk_to_manage_sg = self.network_service.find_security_group(
            talk_to_manage_sg_name
        )
        if not self.talk_to_manage_sg:
            raise Exception(f"Security group {talk_to_manage_sg_name} not found")

    def deploy_hosts(self, batch_size: int = 10, use_base_image=True) -> None:
        """
        Deploy all hosts from a network topology to OpenStack in batches.

        Args:
            topology: NetworkTopology object containing host specifications
            batch_size: Number of hosts to deploy simultaneously (default: 10)
        """
        self.logger.info(f"Starting host deployment for topology: {self.topology.name}")

        # Get all hosts from the topology
        hosts = self.topology.get_all_hosts()
        self.logger.info(
            f"Found {len(hosts)} hosts to deploy in batches of {batch_size}"
        )

        if not hosts:
            self.logger.info("No hosts found in topology")
            return

        # Deploy hosts in batches
        for i in range(0, len(hosts), batch_size):
            batch = hosts[i : i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = ((len(hosts) - 1) // batch_size) + 1

            self.logger.info(
                f"Deploying batch {batch_num}/{total_batches} ({len(batch)} hosts)"
            )
            self._deploy_host_batch(batch, use_base_image=use_base_image)

    def _deploy_host_batch(self, hosts: List[Host], use_base_image=True) -> None:
        """
        Deploy a batch of hosts to OpenStack without waiting for completion.

        Args:
            hosts: List of Host objects to deploy
            topology: Parent topology for context
        """
        # Create all instances without waiting for completion
        created_instances: List[Tuple[Host, Any]] = []

        for host in hosts:
            instance = self._deploy_host(
                host, wait_for_active=False, use_base_image=use_base_image
            )
            created_instances.append((host, instance))
            self.logger.info(
                f"Submitted instance creation: {host.name} with ID: {instance.id}"
            )

        # Poll for all instances to become active
        self.logger.info(
            f"Polling for {len(created_instances)} instances to become active..."
        )
        self._poll_instances_until_active(created_instances)

    def _deploy_host(
        self, host: Host, wait_for_active: bool = True, use_base_image=True
    ):
        """
        Deploy a single host to OpenStack.

        Args:
            host: Host object to deploy
            topology: Parent topology for context
        """
        self.logger.info(f"Deploying host: {host.name}")

        # Check if instance already exists
        existing_instance = self.compute_service.find_server(host.name)
        if existing_instance:
            raise ValueError(f"Instance {host.name} already exists")

        # Get the network for this host
        network = self._find_host_network(host)
        if not network:
            raise ValueError(f"Could not find network for host {host.name}")

        # Get image: host.image_name takes priority (data-driven), then
        # fall back to legacy flows (name-derived baked image or OS mapping).
        if host.image_name:
            image = self._get_image(host.image_name)
        elif use_base_image:
            image = self._get_image_for_os(host.os_type)
        else:
            image = self._get_image(get_image_name(host.name))

        # Get flavor
        flavor = self._get_flavor(host.flavor)

        # Prepare security groups
        security_groups = self._get_security_groups_for_host(host)
        security_groups.append({"name": self.talk_to_manage_sg.name})

        # Prepare instance creation parameters
        instance_params = {
            "name": host.name,
            "imageRef": image.id,  # Use image ID, not full object
            "flavorRef": flavor.id,  # Use flavor ID, not full object
            "networks": [{"uuid": network.id}],
            "security_groups": security_groups,
            "key_name": self.manage_ssh_key_name,
        }

        # Add fixed IP if specified
        if host.ip_address:
            instance_params["networks"][0]["fixed_ip"] = str(host.ip_address)

        # Create the instance
        instance = self.compute_service.create_server(**instance_params)
        self.created_instances[host.name] = instance
        self.logger.info(f"Created instance: {host.name} with ID: {instance.id}")

        if wait_for_active:
            # Wait for instance to become active
            instance = self.compute_service.wait_for_server(instance)
            self.logger.info(f"Instance {host.name} is now active")

        return instance

    def _poll_instances_until_active(
        self,
        instances: List[Tuple[Host, Any]],
        poll_interval: int = 5,
        max_wait: int = 600,
    ) -> None:
        """
        Poll instances until they become active.

        Args:
            instances: List of (host, instance) tuples to poll
            poll_interval: Time to wait between polls in seconds
            max_wait: Maximum time to wait in seconds
        """
        start_time = time.time()
        pending_instances = {
            instance.id: (host, instance) for host, instance in instances
        }

        while pending_instances and (time.time() - start_time) < max_wait:
            # Check status of all pending instances
            completed_this_round = []

            for instance_id, (host, instance) in pending_instances.items():
                # Get current instance status
                current_instance = self.compute_service.get_server(instance_id)

                if current_instance.status == "ACTIVE":
                    self.logger.info(f"Instance {host.name} is now active")
                    completed_this_round.append(instance_id)
                elif current_instance.status == "ERROR":
                    raise Exception(
                        f"Instance {host.name} failed to deploy: {getattr(current_instance, 'fault', 'Unknown error')}"
                    )
                else:
                    self.logger.debug(
                        f"Instance {host.name} status: {current_instance.status}"
                    )

            # Remove completed instances from pending list
            for instance_id in completed_this_round:
                del pending_instances[instance_id]

            # If there are still pending instances, wait before next poll
            if pending_instances:
                remaining_count = len(pending_instances)
                elapsed_time = int(time.time() - start_time)
                self.logger.info(
                    f"Still waiting for {remaining_count} instances to become active ({elapsed_time}s elapsed)"
                )
                time.sleep(poll_interval)

        # Check if any instances didn't complete
        if pending_instances:
            failed_hosts = [host.name for host, _ in pending_instances.values()]
            raise Exception(
                f"Timeout waiting for instances to become active: {failed_hosts}"
            )

        self.logger.info("All instances are now active")

    def _find_host_network(self, host: Host) -> Optional[Any]:
        """
        Find the OpenStack network that should contain this host.

        Args:
            host: Host to find network for
            topology: Topology containing the host

        Returns:
            OpenStack network object or None if not found
        """
        # Find which subnet contains this host
        for network in self.topology.networks:
            for subnet in network.subnets:
                if host in subnet.hosts:
                    os_network = self.network_service.find_network(subnet.name)
                    if os_network:
                        return os_network
                    else:
                        raise ValueError(f"OpenStack network {subnet.name} not found")

        return None

    def _get_image_for_os(self, os_type: OSType) -> Any:
        """
        Get OpenStack image for the given OS type.

        Args:
            os_type: OS type from Perry specification

        Returns:
            OpenStack image object

        Raises:
            ValueError: If image not found for OS type
        """
        image_name = self.os_image_mapping.get(os_type)
        if not image_name:
            raise ValueError(f"No image mapping defined for OS type: {os_type}")

        image = self.compute_service.find_image(image_name)
        if not image:
            raise ValueError(f"Image {image_name} not found in OpenStack")

        return image

    def _get_image(self, image_name: str) -> Any:
        image = self.compute_service.find_image(image_name)
        if not image:
            raise ValueError(f"Image {image_name} not found in OpenStack")
        return image

    def _get_flavor(self, flavor_type: FlavorType) -> Any:
        """
        Get OpenStack flavor for the given flavor type.

        Args:
            flavor_type: Flavor type from Perry specification

        Returns:
            OpenStack flavor object

        Raises:
            ValueError: If flavor not found
        """
        flavor_name = self.flavor_mapping.get(flavor_type)
        if not flavor_name:
            raise ValueError(
                f"No flavor mapping defined for flavor type: {flavor_type}"
            )

        flavor = self.compute_service.find_flavor(flavor_name)
        if not flavor:
            raise ValueError(f"Flavor {flavor_name} not found in OpenStack")

        return flavor

    def _get_security_groups_for_host(self, host: Host) -> List[Dict[str, str]]:
        """
        Get security groups for a host.

        Args:
            host: Host object

        Returns:
            List of security group references for OpenStack
        """

        # Get host's subnet
        subnet = self.topology.get_subnet_for_host(host)
        if not subnet:
            raise Exception(f"Subnet for host {host.name} not found")

        security_groups = [{"name": subnet.sg_name}]

        return security_groups
