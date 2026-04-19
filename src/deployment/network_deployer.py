from __future__ import annotations

import logging
import time

from openstack.connection import Connection

from config.config import Config
from src.abstractions.network import NetworkTopology

logger = logging.getLogger(__name__)


class NetworkDeployer:

    def __init__(self, conn: Connection, config: Config) -> None:
        self._conn = conn
        self._project_id = conn.current_project_id

    def deploy(self, topology: NetworkTopology) -> None:
        ext_net = self._conn.network.find_network("external")
        if not ext_net:
            raise RuntimeError("External network 'external' not found in OpenStack.")

        router = self._conn.network.create_router(
            name="router",
            admin_state_up=True,
            external_gateway_info={"network_id": ext_net.id},
        )
        deadline = time.monotonic() + 60
        while self._conn.network.get_router(router.id).status != "ACTIVE":
            if time.monotonic() > deadline:
                raise TimeoutError("Router did not reach ACTIVE within 60s.")
            time.sleep(2)
        logger.info("Created router")

        for subnet in topology.get_all_subnets():
            os_net = self._conn.network.create_network(
                name=subnet.name,
                admin_state_up=True,
            )
            deadline = time.monotonic() + 60
            while self._conn.network.get_network(os_net.id).status != "ACTIVE":
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Network '{subnet.name}' did not reach ACTIVE within 60s.")
                time.sleep(2)

            os_subnet = self._conn.network.create_subnet(
                name=f"{subnet.name}-subnet",
                network_id=os_net.id,
                ip_version=4,
                cidr=str(subnet.cidr),
                enable_dhcp=True,
                dns_nameservers=subnet.dns_servers,
            )
            self._conn.network.add_interface_to_router(router.id, subnet_id=os_subnet.id)
            deadline = time.monotonic() + 60
            while self._conn.network.get_router(router.id).status != "ACTIVE":
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Router did not return to ACTIVE after attaching '{subnet.name}'.")
                time.sleep(2)
            logger.info("Created network + subnet: %s", subnet.name)

        for subnet in topology.get_all_subnets():
            sg = self._conn.network.create_security_group(
                name=subnet.sg_name,
                description=f"Security group for {subnet.name}",
            )
            if subnet.external:
                for direction in ("ingress", "egress"):
                    self._conn.network.create_security_group_rule(
                        security_group_id=sg.id, direction=direction, remote_ip_prefix="0.0.0.0/0",
                    )
            else:
                for direction in ("ingress", "egress"):
                    self._conn.network.create_security_group_rule(
                        security_group_id=sg.id, direction=direction, remote_ip_prefix=str(subnet.cidr),
                    )
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
                            self._conn.network.create_security_group_rule(
                                security_group_id=sg.id, direction=direction, remote_ip_prefix=str(peer.cidr),
                            )
            logger.info("Created security group: %s", subnet.sg_name)

    def teardown(self, topology: NetworkTopology) -> None:
        pid = self._project_id

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
