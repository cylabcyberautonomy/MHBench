from __future__ import annotations

import logging
import sys
import tempfile
import time
from pathlib import Path

import ansible_runner
from openstack.connection import Connection

from config.config import Config
from src.abstractions.network import NetworkTopology
from src.deployment.online_registry_service import OnlineRegistryService
from src.playbooks.playbook_registry_service import PlaybookRegistryService

logger = logging.getLogger(__name__)

_MHBENCH_DIR = Path(__file__).resolve().parent.parent.parent
_CONSOLE_TAIL_LINES = 100
_PLAYBOOK_RETRIES = 3
_PLAYBOOK_RETRY_DELAY = 15


class AnsibleRunner:

    def __init__(
        self,
        config: Config,
        online_registry: OnlineRegistryService,
        playbook_registry: PlaybookRegistryService,
        conn: Connection | None = None,
        project_name: str | None = None,
    ) -> None:
        self._ssh_key_path = config.openstack.ssh_key_path
        self._online = online_registry
        self._playbook_registry = playbook_registry
        self._conn = conn
        self._project_name = project_name
        c2c = getattr(config, "c2c", None)
        self._c2c_vars: dict = {"caldera_ip": c2c.ip, "caldera_port": c2c.port} if c2c else {}

    def _log_console(self, host_name: str) -> None:
        if not self._conn:
            return
        full_name = f"{self._project_name}-{host_name}" if self._project_name else host_name
        server = self._conn.compute.find_server(full_name)
        if not server:
            logger.warning("Could not find server '%s' to fetch console log", full_name)
            return
        try:
            output = self._conn.compute.get_server_console_output(server.id, length=_CONSOLE_TAIL_LINES)
            console_text = output.get("output", "") if isinstance(output, dict) else str(output)
            logger.info("Console log for %s (last %d lines):\n%s", full_name, _CONSOLE_TAIL_LINES, console_text)
        except Exception:
            logger.exception("Failed to fetch console log for '%s'", full_name)

    def _run_playbook(self, pb_name: str, inventory: dict, extravars: dict, tmp: str, project_dir: str) -> None:
        pb_path = self._playbook_registry.get_path(pb_name)
        def _stream(event: dict) -> bool:
            line = event.get("stdout", "")
            if line:
                print(line, end="", flush=True)
            return True

        for attempt in range(1, _PLAYBOOK_RETRIES + 1):
            result = ansible_runner.run(
                private_data_dir=tmp,
                project_dir=project_dir,
                playbook=pb_path.name,
                inventory=inventory,
                extravars=extravars,
                event_handler=_stream,
                quiet=True,
                envvars={
                    "ANSIBLE_SSH_ARGS": (
                        "-o ControlMaster=no "
                        "-o ControlPath=none "
                        "-o StrictHostKeyChecking=no "
                        "-o UserKnownHostsFile=/dev/null "
                        "-o ServerAliveInterval=30 "
                        "-o ServerAliveCountMax=10"
                    ),
                    "ANSIBLE_PIPELINING": "True",
                    "ANSIBLE_SSH_RETRIES": "3",
                }
            )
            if result.status == "successful":
                return
            stderr = result.stderr.read() if result.stderr else ""
            if attempt < _PLAYBOOK_RETRIES:
                logger.warning(
                    "Playbook '%s' failed (attempt %d/%d, status: %s) — retrying in %ds.\n%s",
                    pb_name, attempt, _PLAYBOOK_RETRIES, result.status, _PLAYBOOK_RETRY_DELAY, stderr,
                )
                time.sleep(_PLAYBOOK_RETRY_DELAY)
            else:
                raise RuntimeError(
                    f"Playbook '{pb_name}' failed after {_PLAYBOOK_RETRIES} attempts (status: {result.status}).\n{stderr}"
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
                    f'-vvv '
                    f'-o ControlMaster=no '
                    f'-o ControlPath=none '
                    f'-o StrictHostKeyChecking=no '
                    f'-o UserKnownHostsFile=/dev/null '
                    f'-o ServerAliveInterval=30 '
                    f'-o ServerAliveCountMax=10 '
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
                try:
                    self._run_playbook(
                        pb_name,
                        {"all": {"hosts": inventory_hosts}},
                        extravars,
                        tmp,
                        project_dir,
                    )
                except RuntimeError:
                    if host_name:
                        self._log_console(host_name)
                    raise
