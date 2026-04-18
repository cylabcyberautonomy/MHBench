from __future__ import annotations

import logging
import time

from openstack.connection import Connection

from config.config import Config
from src.abstractions.network import Host, NetworkTopology
from src.deployment.online_registry_service import OnlineRegistryService

logger = logging.getLogger(__name__)

_BATCH_SIZE = 10
_DEPLOY_TIMEOUT = 600
_DELETE_TIMEOUT = 300
_POLL_INTERVAL = 5


class HostDeployer:

    def __init__(self, conn: Connection, config: Config, online_registry: OnlineRegistryService) -> None:
        self._conn = conn
        self._project_id = conn.current_project_id
        self._ssh_key_name = config.openstack.ssh_key_name
        self._online = online_registry

    def deploy(self, topology: NetworkTopology) -> None:
        hosts = topology.get_all_hosts()
        for i in range(0, len(hosts), _BATCH_SIZE):
            batch = hosts[i:i + _BATCH_SIZE]
            pending: dict[str, Host] = {}

            for host in batch:
                base_image_name = self._online.get_base_image(host.vm_type)
                image = self._conn.image.find_image(base_image_name)
                if not image:
                    raise RuntimeError(f"Image '{base_image_name}' not found in Glance.")

                flavor = self._conn.compute.find_flavor(host.flavor)
                if not flavor:
                    raise RuntimeError(f"Flavor '{host.flavor}' not found in OpenStack.")

                subnet = topology.get_subnet_for_host(host)
                if not subnet:
                    raise RuntimeError(f"No subnet found for host '{host.name}'.")
                os_net = self._conn.network.find_network(subnet.name, project_id=self._project_id)
                if not os_net:
                    raise RuntimeError(f"OpenStack network '{subnet.name}' not found.")

                network_spec: dict = {"uuid": os_net.id}
                if host.ip_address:
                    network_spec["fixed_ip"] = str(host.ip_address)

                server = self._conn.compute.create_server(
                    name=host.name,
                    imageRef=image.id,
                    flavorRef=flavor.id,
                    networks=[network_spec],
                    security_groups=[{"name": subnet.sg_name}],
                    key_name=self._ssh_key_name,
                )
                pending[server.id] = host
                logger.info("Submitted: %s", host.name)

            deadline = time.monotonic() + _DEPLOY_TIMEOUT
            while pending:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Timed out waiting for: {[h.name for h in pending.values()]}")
                time.sleep(_POLL_INTERVAL)
                done = []
                for server_id, host in pending.items():
                    current = self._conn.compute.get_server(server_id)
                    if current.status == "ACTIVE":
                        logger.info("Active: %s", host.name)
                        done.append(server_id)
                    elif current.status == "ERROR":
                        raise RuntimeError(f"Instance '{host.name}' entered ERROR: {getattr(current, 'fault', 'unknown')}")
                for server_id in done:
                    del pending[server_id]

    def teardown(self, topology: NetworkTopology) -> None:
        pending: dict[str, str] = {}
        for host in topology.get_all_hosts():
            matches = list(self._conn.compute.servers(name=host.name, project_id=self._project_id))
            for server in matches:
                self._conn.compute.delete_server(server.id, force=True)
                pending[server.id] = host.name
                logger.info("Deleting: %s", host.name)

        deadline = time.monotonic() + _DELETE_TIMEOUT
        while pending:
            if time.monotonic() > deadline:
                raise TimeoutError(f"Timed out waiting for deletion of: {list(pending.values())}")
            time.sleep(_POLL_INTERVAL)
            gone = [sid for sid in pending if self._conn.compute.find_server(sid) is None]
            for sid in gone:
                logger.info("Deleted: %s", pending.pop(sid))
