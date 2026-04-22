from __future__ import annotations

import logging

from openstack.connection import Connection

from config.config import Config
from src.abstractions.network import NetworkTopology
from src.deployment.ansible_runner import AnsibleRunner
from src.deployment.host_deployer import HostDeployer
from src.deployment.network_deployer import NetworkDeployer
from src.deployment.online_registry_service import OnlineRegistryService
from src.playbooks.playbook_registry_service import PlaybookRegistryService

logger = logging.getLogger(__name__)


class DeploymentOrchestrator:

    def __init__(
        self,
        conn: Connection,
        config: Config,
        online_registry: OnlineRegistryService,
        playbook_registry: PlaybookRegistryService,
        project_name: str | None = None,
    ) -> None:
        self._conn = conn
        self._config = config
        self._online = online_registry
        self._playbook_registry = playbook_registry
        self._project_name = project_name

    def provision(self, topology: NetworkTopology) -> str | None:
        logger.info("Provisioning topology: %s", topology.name)
        NetworkDeployer(self._conn, self._config, self._project_name).deploy(topology)
        mgmt_floating_ip = HostDeployer(self._conn, self._config, self._online, self._project_name).deploy(topology)
        logger.info("Provisioning complete: %s", topology.name)
        return mgmt_floating_ip

    def configure(self, topology: NetworkTopology, mgmt_floating_ip: str | None) -> None:
        if mgmt_floating_ip is None:
            logger.info("No management host; skipping Ansible for %s", topology.name)
            return
        logger.info("Configuring topology: %s", topology.name)
        AnsibleRunner(self._config, self._online, self._playbook_registry, self._conn, self._project_name).run(topology, mgmt_floating_ip)
        logger.info("Configuration complete: %s", topology.name)

    def deploy(self, topology: NetworkTopology) -> None:
        logger.info("Deploying topology: %s", topology.name)
        mgmt_floating_ip = self.provision(topology)
        self.configure(topology, mgmt_floating_ip)
        logger.info("Deployment complete: %s", topology.name)

    def teardown(self, topology: NetworkTopology) -> None:
        logger.info("Tearing down topology: %s", topology.name)
        HostDeployer(self._conn, self._config, self._online, self._project_name).teardown(topology)
        NetworkDeployer(self._conn, self._config, self._project_name).teardown(topology)
        logger.info("Teardown complete: %s", topology.name)
