from __future__ import annotations

import logging

from config.config import Config
from src.abstractions.network import NetworkTopology
from src.deployment.backends.base import CloudBackend
from src.deployment.host_deployer import HostDeployer
from src.deployment.network_deployer import NetworkDeployer
from src.deployment.online_registry_service import OnlineRegistryService
from src.deployment.openstack_client import build_connection
from src.deployment.upload_manager import UploadManager

logger = logging.getLogger(__name__)


class OpenStackBackend(CloudBackend):
    """OpenStack provider — a thin adapter over the original, battle-tested
    NetworkDeployer / HostDeployer / UploadManager. Behaviour of the OpenStack
    path is intentionally identical to before the backend abstraction existed."""

    name = "openstack"

    def __init__(self, config: Config, online_registry: OnlineRegistryService, project_name: str | None = None) -> None:
        if config.openstack is None:
            raise ValueError("openstack config block is required for the OpenStack backend.")
        self._config = config
        self._online = online_registry
        self._project_name = project_name
        self._conn = build_connection(config.openstack)

    @property
    def conn(self):  # exposed for callers that still want the raw SDK connection
        return self._conn

    def add_management_ingress(self, port: int, sources: list[str]) -> None:
        from openstack.exceptions import ConflictException
        sg_name = f"{self._project_name}-management_sg" if self._project_name else "management_sg"
        sg = self._conn.network.find_security_group(sg_name, project_id=self._conn.current_project_id)
        if not sg:
            logger.warning("management_sg %r not found; cannot open tcp/%d", sg_name, port)
            return
        for src in sources:
            try:
                self._conn.network.create_security_group_rule(
                    security_group_id=sg.id, direction="ingress", protocol="tcp",
                    port_range_min=port, port_range_max=port, remote_ip_prefix=src)
                logger.info("management_sg: opened tcp/%d from %s", port, src)
            except ConflictException:
                pass

    def provision_network(self, topology: NetworkTopology) -> None:
        NetworkDeployer(self._conn, self._config, self._project_name).deploy(topology)

    def provision_hosts(self, topology: NetworkTopology) -> str | None:
        return HostDeployer(self._conn, self._config, self._online, self._project_name).deploy(topology)

    def _host_deployer(self) -> HostDeployer:
        return HostDeployer(self._conn, self._config, self._online, self._project_name)

    def create_host(self, host, subnet) -> str:
        return self._host_deployer().create_one_host(host, subnet)

    def rebuild_host(self, display_name: str) -> None:
        self._host_deployer().rebuild_one(display_name)

    def remove_host(self, display_name: str) -> None:
        self._host_deployer().delete_one(display_name)

    def teardown_hosts(self, topology: NetworkTopology) -> None:
        HostDeployer(self._conn, self._config, self._online, self._project_name).teardown(topology)

    def teardown_network(self, topology: NetworkTopology) -> None:
        NetworkDeployer(self._conn, self._config, self._project_name).teardown(topology)

    def get_console_output(self, host_full_name: str, length: int | None = None) -> str | None:
        server = self._conn.compute.find_server(host_full_name)
        if not server:
            logger.warning("Could not find server '%s' to fetch console log", host_full_name)
            return None
        try:
            output = self._conn.compute.get_server_console_output(server.id, length=length)
            return output.get("output", "") if isinstance(output, dict) else str(output)
        except Exception:
            logger.exception("Failed to fetch console log for '%s'", host_full_name)
            return None

    def upload_image(self, name: str, location: str, force: bool = False) -> None:
        UploadManager(self._conn, self._config, None).upload_image_from(name, location, force=force)

    def delete_image(self, name: str) -> None:
        UploadManager(self._conn, self._config, None).delete_image(name)
