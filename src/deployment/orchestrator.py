from __future__ import annotations

import logging

from config.config import Config
from src.abstractions.network import NetworkTopology
from src.deployment.ansible_runner import AnsibleRunner
from src.deployment.backends.base import CloudBackend
from src.deployment.online_registry_service import OnlineRegistryService
from src.playbooks.playbook_registry_service import PlaybookRegistryService

logger = logging.getLogger(__name__)


class DeploymentOrchestrator:

    def __init__(
        self,
        backend: CloudBackend,
        config: Config,
        online_registry: OnlineRegistryService,
        playbook_registry: PlaybookRegistryService,
        project_name: str | None = None,
    ) -> None:
        self._backend = backend
        self._config = config
        self._online = online_registry
        self._playbook_registry = playbook_registry
        self._project_name = project_name

    def _ansible(self) -> AnsibleRunner:
        return AnsibleRunner(self._config, self._online, self._playbook_registry, self._backend, self._project_name)

    def provision(self, topology: NetworkTopology) -> str | None:
        logger.info("Provisioning topology: %s", topology.name)
        self._backend.provision_network(topology)
        mgmt_floating_ip = self._backend.provision_hosts(topology)
        logger.info("Provisioning complete: %s", topology.name)
        return mgmt_floating_ip

    def configure(self, topology: NetworkTopology, mgmt_floating_ip: str | None) -> None:
        if mgmt_floating_ip is None:
            logger.info("No management host; skipping Ansible for %s", topology.name)
            return
        logger.info("Configuring topology: %s", topology.name)
        self._ansible().run_parallel(topology, mgmt_floating_ip)
        logger.info("Configuration complete: %s", topology.name)

    def collect(self, topology: NetworkTopology, mgmt_floating_ip: str | None, dest: str) -> None:
        if mgmt_floating_ip is None:
            logger.info("No management host; skipping log collection for %s", topology.name)
            return
        logger.info("Collecting host logs: %s", topology.name)
        self._ansible().collect(topology, mgmt_floating_ip, dest)
        logger.info("Log collection complete: %s", topology.name)

    def rotate_logs(self, topology: NetworkTopology, mgmt_floating_ip: str | None) -> None:
        if mgmt_floating_ip is None:
            logger.info("No management host; skipping log rotation for %s", topology.name)
            return
        logger.info("Rotating host logs: %s", topology.name)
        self._ansible().rotate_logs(topology, mgmt_floating_ip)
        logger.info("Log rotation complete: %s", topology.name)

    def deploy(self, topology: NetworkTopology) -> None:
        logger.info("Deploying topology: %s", topology.name)
        mgmt_floating_ip = self.provision(topology)
        self.configure(topology, mgmt_floating_ip)
        logger.info("Deployment complete: %s", topology.name)

    def teardown(self, topology: NetworkTopology) -> None:
        logger.info("Tearing down topology: %s", topology.name)
        self._backend.teardown_hosts(topology)
        self._backend.teardown_network(topology)
        logger.info("Teardown complete: %s", topology.name)
