from __future__ import annotations

import logging

from openstack.connection import Connection

from config.config import Config
from src.abstractions.network import NetworkTopology
from src.deployment.host_deployer import HostDeployer
from src.deployment.network_deployer import NetworkDeployer
from src.deployment.online_registry_service import OnlineRegistryService

logger = logging.getLogger(__name__)


class DeploymentOrchestrator:

    def __init__(self, conn: Connection, config: Config, online_registry: OnlineRegistryService) -> None:
        self._conn = conn
        self._config = config
        self._online = online_registry

    def deploy(self, topology: NetworkTopology) -> None:
        logger.info("Deploying topology: %s", topology.name)
        NetworkDeployer(self._conn, self._config).deploy(topology)
        HostDeployer(self._conn, self._config, self._online).deploy(topology)
        logger.info("Deployment complete: %s", topology.name)

    def teardown(self, topology: NetworkTopology) -> None:
        logger.info("Tearing down topology: %s", topology.name)
        HostDeployer(self._conn, self._config, self._online).teardown(topology)
        NetworkDeployer(self._conn, self._config).teardown(topology)
        logger.info("Teardown complete: %s", topology.name)
