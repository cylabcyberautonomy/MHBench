from __future__ import annotations

import logging
import time

from openstack.connection import Connection
from openstack.exceptions import ConflictException

from config.config import Config
from src.abstractions.network import NetworkTopology

logger = logging.getLogger(__name__)


class NetworkDeployer:

    def __init__(self, conn: Connection, config: Config) -> None:
        self._conn = conn
        self._project_id = conn.current_project_id
        self._management = config.management

    def deploy(self, topology: NetworkTopology) -> None:
        ext_net = self._conn.network.find_network("external")
        if not ext_net:
            raise RuntimeError("External network 'external' not found in OpenStack.")

        logger.info("Creating router...")
        router = self._conn.network.create_router(
            name="router",
            admin_state_up=True,
            external_gateway_info={"network_id": ext_net.id},
        )
        time.sleep(1)
        deadline = time.monotonic() + 60
        while self._conn.network.get_router(router.id).status != "ACTIVE":
            if time.monotonic() > deadline:
                raise TimeoutError("Router did not reach ACTIVE within 60s.")
            time.sleep(2)
        logger.info("Router ACTIVE")

        if self._management:
            mgmt = self._management
            logger.info("Creating management_network...")
            os_mgmt_net = self._conn.network.create_network(name="management_network", admin_state_up=True)
            time.sleep(1)
            deadline = time.monotonic() + 60
            while self._conn.network.get_network(os_mgmt_net.id).status != "ACTIVE":
                if time.monotonic() > deadline:
                    raise TimeoutError("Network 'management_network' did not reach ACTIVE within 60s.")
                time.sleep(2)
            logger.info("management_network ACTIVE — creating management_subnet...")
            os_mgmt_subnet = self._conn.network.create_subnet(
                name="management_subnet",
                network_id=os_mgmt_net.id,
                ip_version=4,
                cidr=mgmt.cidr,
                enable_dhcp=True,
                dns_nameservers=["8.8.8.8"],
            )
            time.sleep(1)
            logger.info("Attaching management_subnet to router...")
            self._conn.network.add_interface_to_router(router.id, subnet_id=os_mgmt_subnet.id)
            time.sleep(1)
            deadline = time.monotonic() + 60
            while self._conn.network.get_router(router.id).status != "ACTIVE":
                if time.monotonic() > deadline:
                    raise TimeoutError("Router did not return to ACTIVE after attaching 'management_subnet'.")
                time.sleep(2)
            logger.info("Router ACTIVE after management_subnet attach — waiting for DHCP agent...")
            deadline = time.monotonic() + 60
            while not list(self._conn.network.network_hosting_dhcp_agents(os_mgmt_net.id)):
                if time.monotonic() > deadline:
                    raise TimeoutError("DHCP agent did not pick up 'management_network' within 60s.")
                time.sleep(2)
            logger.info("DHCP agent ready for management_network")

        for subnet in topology.get_all_subnets():
            logger.info("Creating network '%s'...", subnet.name)
            os_net = self._conn.network.create_network(
                name=subnet.name,
                admin_state_up=True,
            )
            time.sleep(1)
            deadline = time.monotonic() + 60
            while self._conn.network.get_network(os_net.id).status != "ACTIVE":
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Network '{subnet.name}' did not reach ACTIVE within 60s.")
                time.sleep(2)
            logger.info("Network '%s' ACTIVE — creating subnet...", subnet.name)

            os_subnet = self._conn.network.create_subnet(
                name=f"{subnet.name}-subnet",
                network_id=os_net.id,
                ip_version=4,
                cidr=str(subnet.cidr),
                enable_dhcp=True,
                dns_nameservers=subnet.dns_servers,
            )
            time.sleep(1)
            logger.info("Attaching '%s-subnet' to router...", subnet.name)
            self._conn.network.add_interface_to_router(router.id, subnet_id=os_subnet.id)
            time.sleep(1)
            deadline = time.monotonic() + 60
            while self._conn.network.get_router(router.id).status != "ACTIVE":
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Router did not return to ACTIVE after attaching '{subnet.name}'.")
                time.sleep(2)
            logger.info("Router ACTIVE after '%s' attach — waiting for DHCP agent...", subnet.name)
            deadline = time.monotonic() + 60
            while not list(self._conn.network.network_hosting_dhcp_agents(os_net.id)):
                if time.monotonic() > deadline:
                    raise TimeoutError(f"DHCP agent did not pick up '{subnet.name}' within 60s.")
                time.sleep(2)
            logger.info("DHCP agent ready for '%s'", subnet.name)

        for subnet in topology.get_all_subnets():
            logger.info("Creating security group '%s'...", subnet.sg_name)
            sg = self._conn.network.create_security_group(
                name=subnet.sg_name,
                description=f"Security group for {subnet.name}",
            )
            time.sleep(1)
            if subnet.external:
                for direction in ("ingress", "egress"):
                    try:
                        self._conn.network.create_security_group_rule(
                            security_group_id=sg.id, direction=direction, remote_ip_prefix="0.0.0.0/0",
                        )
                    except ConflictException:
                        pass
                    time.sleep(1)
            else:
                for direction in ("ingress", "egress"):
                    try:
                        self._conn.network.create_security_group_rule(
                            security_group_id=sg.id, direction=direction, remote_ip_prefix=str(subnet.cidr),
                        )
                    except ConflictException:
                        pass
                    time.sleep(1)
                peers: set[str] = set()
                for conn in topology.subnet_connections:
                    if conn.from_subnet == subnet.name:
                        peers.add(conn.to_subnet)
                    elif conn.bidirectional and conn.to_subnet == subnet.name:
                        peers.add(conn.from_subnet)
                for peer_name in peers:
                    peer = topology.get_subnet_by_name(peer_name)
                    if peer:
                        for direction in ("ingress", "egress"):
                            try:
                                self._conn.network.create_security_group_rule(
                                    security_group_id=sg.id, direction=direction, remote_ip_prefix=str(peer.cidr),
                                )
                            except ConflictException:
                                pass
                            time.sleep(1)
                if self._management:
                    for direction in ("ingress", "egress"):
                        try:
                            self._conn.network.create_security_group_rule(
                                security_group_id=sg.id, direction=direction,
                                remote_ip_prefix=self._management.cidr,
                            )
                        except ConflictException:
                            pass
                        time.sleep(1)
            logger.info("Security group '%s' ready", subnet.sg_name)

        if self._management:
            logger.info("Creating security group 'management_sg'...")
            mgmt_sg = self._conn.network.create_security_group(
                name="management_sg",
                description="Security group for management network",
            )
            time.sleep(1)
            for direction in ("ingress", "egress"):
                try:
                    self._conn.network.create_security_group_rule(
                        security_group_id=mgmt_sg.id, direction=direction, remote_ip_prefix="0.0.0.0/0",
                    )
                except ConflictException:
                    pass
                time.sleep(1)
            logger.info("Security group 'management_sg' ready")

    def teardown(self, topology: NetworkTopology) -> None:
        pid = self._project_id

        if self._management:
            for sg in self._conn.network.security_groups(name="management_sg", project_id=pid):
                self._conn.network.delete_security_group(sg.id)
                logger.info("Deleted security group: management_sg")

        for subnet in topology.get_all_subnets():
            for sg in self._conn.network.security_groups(name=subnet.sg_name, project_id=pid):
                self._conn.network.delete_security_group(sg.id)
                logger.info("Deleted security group: %s", subnet.sg_name)

        for router in self._conn.network.routers(name="router", project_id=pid):
            for subnet in topology.get_all_subnets():
                for os_subnet in self._conn.network.subnets(name=f"{subnet.name}-subnet", project_id=pid):
                    try:
                        self._conn.network.remove_interface_from_router(router.id, subnet_id=os_subnet.id)
                    except Exception:
                        pass
            if self._management:
                for os_subnet in self._conn.network.subnets(name="management_subnet", project_id=pid):
                    try:
                        self._conn.network.remove_interface_from_router(router.id, subnet_id=os_subnet.id)
                    except Exception:
                        pass
            for port in self._conn.network.ports(device_id=router.id, project_id=pid):
                if port.device_owner == "network:router_interface":
                    try:
                        self._conn.network.remove_interface_from_router(router.id, port_id=port.id)
                    except Exception:
                        pass
            self._conn.network.delete_router(router.id)
            logger.info("Deleted router")

        for subnet in topology.get_all_subnets():
            for os_subnet in self._conn.network.subnets(name=f"{subnet.name}-subnet", project_id=pid):
                self._conn.network.delete_subnet(os_subnet.id)
                logger.info("Deleted subnet: %s-subnet", subnet.name)

        for subnet in topology.get_all_subnets():
            for os_net in self._conn.network.networks(name=subnet.name, project_id=pid):
                self._conn.network.delete_network(os_net.id)
                logger.info("Deleted network: %s", subnet.name)

        if self._management:
            for os_subnet in self._conn.network.subnets(name="management_subnet", project_id=pid):
                self._conn.network.delete_subnet(os_subnet.id)
                logger.info("Deleted subnet: management_subnet")
            for os_net in self._conn.network.networks(name="management_network", project_id=pid):
                self._conn.network.delete_network(os_net.id)
                logger.info("Deleted network: management_network")
