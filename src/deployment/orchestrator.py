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

    # -- per-host dynamic ops (arena dynamic topology interface) --------------------------------------
    # A running defender asks the environment (via the arena) to add a decoy / rebuild a compromised host /
    # remove one. The arena drives these through the CLI (add-host/rebuild-host/remove-host).
    _ROLE_VM_TYPE = {"apache_vuln": "webserver_telemetry", "decoy": "ubuntu_telemetry"}

    def add_host(self, topology: NetworkTopology, name: str, role: str = "decoy",
                 subnet_name: str | None = None, flavor: str = "m1.small") -> dict:
        """Create ONE host (a decoy) on an existing subnet; return {name, ip}. role maps to the backend
        image (apache_vuln -> webserver, decoy -> ubuntu); an unknown role is treated as a literal vm_type."""
        from src.abstractions.network import Host
        vm_type = self._ROLE_VM_TYPE.get(role, role)
        subnet = topology.get_subnet_by_name(subnet_name) if subnet_name else None
        if subnet is None:
            # Default to the first non-external subnet that already holds hosts (the victim plane).
            subnet = next((s for s in topology.get_all_subnets() if s.hosts and not s.external), None)
        if subnet is None:
            raise RuntimeError(f"add_host: could not resolve a subnet (name={subnet_name!r})")
        ip = self._backend.create_host(Host(name=name, vm_type=vm_type, flavor=flavor), subnet)
        logger.info("add_host: %s (%s) on %s -> %s", name, vm_type, subnet.name, ip)
        return {"name": name, "ip": ip}

    def rebuild_host(self, topology: NetworkTopology, target: str) -> dict:
        self._backend.rebuild_host(target)
        return {"ok": True, "target": target}

    def remove_host(self, topology: NetworkTopology, target: str) -> dict:
        self._backend.remove_host(target)
        return {"ok": True, "target": target}
