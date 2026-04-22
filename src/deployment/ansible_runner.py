from __future__ import annotations

import logging
import sys
import tempfile
from pathlib import Path

import ansible_runner

from config.config import Config
from src.abstractions.network import NetworkTopology
from src.deployment.online_registry_service import OnlineRegistryService
from src.playbooks.playbook_registry_service import PlaybookRegistryService

logger = logging.getLogger(__name__)

_MHBENCH_DIR = Path(__file__).resolve().parent.parent.parent


class AnsibleRunner:

    def __init__(
        self,
        config: Config,
        online_registry: OnlineRegistryService,
        playbook_registry: PlaybookRegistryService,
    ) -> None:
        self._ssh_key_path = config.openstack.ssh_key_path
        self._online = online_registry
        self._playbook_registry = playbook_registry
        c2c = getattr(config, "c2c", None)
        self._c2c_vars: dict = {"caldera_ip": c2c.ip, "caldera_port": c2c.port} if c2c else {}

    def _run_playbook(self, pb_name: str, inventory: dict, extravars: dict, tmp: str, project_dir: str) -> None:
        pb_path = self._playbook_registry.get_path(pb_name)
        def _stream(event: dict) -> bool:
            line = event.get("stdout", "")
            if line:
                print(line, end="", flush=True)
            return True

        result = ansible_runner.run(
            private_data_dir=tmp,
            project_dir=project_dir,
            playbook=pb_path.name,
            inventory=inventory,
            extravars=extravars,
            event_handler=_stream,
            quiet=True,
        )
        if result.status != "successful":
            stderr = result.stderr.read() if result.stderr else ""
            raise RuntimeError(
                f"Playbook '{pb_name}' failed (status: {result.status}).\n{stderr}"
            )

    def run(self, topology: NetworkTopology, mgmt_floating_ip: str) -> None:
        hosts = topology.get_all_hosts()
        for host in hosts:
            if host.ip_address is None:
                raise RuntimeError(f"Host '{host.name}' has no ip_address; cannot build ansible inventory.")

        proxy = (
            f"ssh -W %h:%p -i {self._ssh_key_path} "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"root@{mgmt_floating_ip}"
        )
        inventory_hosts = {
            host.name: {
                "ansible_host": str(host.ip_address),
                "ansible_port": 22,
                "ansible_user": "root",
                "ansible_ssh_private_key_file": self._ssh_key_path,
                "ansible_ssh_common_args": (
                    f'-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
                    f'-o ProxyCommand="{proxy}"'
                ),
            }
            for host in hosts
        }

        queue: list[tuple[str | None, str, dict]] = []
        for host in hosts:
            runtime_pbs = self._online.get_runtime_playbooks(host.vm_type)
            if runtime_pbs:
                queue.append((host.name, "check_if_host_up", {
                    "manage_ip": mgmt_floating_ip,
                    "ssh_key_path": self._ssh_key_path,
                }))
                for pb_name in runtime_pbs:
                    queue.append((host.name, pb_name, {"user": "root", **self._c2c_vars}))
        for pb in topology.playbooks:
            queue.append((None, pb.name, pb.args))

        if not queue:
            logger.info("No playbooks to run.")
            return

        first_pb = self._playbook_registry.get_path(queue[0][1])
        project_dir = str((_MHBENCH_DIR / first_pb).resolve().parent)

        with tempfile.TemporaryDirectory() as tmp:
            for host_name, pb_name, args in queue:
                extravars = {"host": host_name, **args} if host_name else args
                if host_name:
                    logger.info("Running playbook '%s' on '%s'", pb_name, host_name)
                else:
                    logger.info("Running topology playbook '%s'", pb_name)
                self._run_playbook(
                    pb_name,
                    {"all": {"hosts": inventory_hosts}},
                    extravars,
                    tmp,
                    project_dir,
                )
