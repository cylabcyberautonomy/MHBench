import ansible_runner

from rich import print
import tempfile
import time
import uuid

from .ansible_playbook import AnsiblePlaybook

from contextlib import redirect_stdout
from os import path

from src.utility.logging import get_logger

logger = get_logger()


class AnsibleRunner:
    def __init__(self, ssh_key_path, management_ip, ansible_dir, log_path, quiet=False, verbosity=4):
        self.ssh_key_path = ssh_key_path
        self.management_ip = management_ip
        self.ansible_dir = ansible_dir
        self.quiet = quiet
        self.verbosity = verbosity
        self.log_path = log_path
        self.MAX_RETRIES = 5

        # Per-process temp directory for ansible_runner's writable state
        # (env/extravars, env/envvars, artifacts/).  Using a unique dir per
        # AnsibleRunner instance prevents parallel MHBench subprocesses from
        # racing on the shared ./ansible/env/ files.  Playbooks remain in
        # ansible_dir, referenced via project_dir.
        self._runner_tmp = tempfile.TemporaryDirectory(prefix="mhbench-ansible-")

        self.ansible_vars_default = {
            "manage_ip": self.management_ip,
            "ssh_key_path": self.ssh_key_path,
        }

    def run_playbook(self, playbook: AnsiblePlaybook):
        if self.quiet is False:
            print(f"\n")
            print(f"[RUNNING PLAYBOOK]    {playbook.name}")
            print(f"[PLAYBOOK  PARAMS]    {playbook.params}")

        log_path = path.join(self.log_path, f"ansible_log_{uuid.uuid4().hex}.log")

        ansible_result = None
        for attempt in range(self.MAX_RETRIES):
            with tempfile.TemporaryDirectory(prefix="mhbench-run-") as run_tmp:
                # Merge default params with playbook specific params
                playbook_full_params = self.ansible_vars_default | playbook.params
                manage_slug = (self.management_ip or "default").replace(".", "_")
                control_path_dir = f"/tmp/ansible-cp-{manage_slug}"
                ansible_result = ansible_runner.run(
                    extravars=playbook_full_params,
                    private_data_dir=run_tmp,
                    project_dir=path.abspath(self.ansible_dir),
                    inventory=path.abspath(path.join(self.ansible_dir, "inventory")),
                    playbook=playbook.name,
                    cancel_callback=lambda: None,
                    quiet=self.quiet,
                    verbosity=self.verbosity,
                    envvars={
                        "ANSIBLE_SSH_CONTROL_PATH_DIR": control_path_dir,
                        "ANSIBLE_HOST_KEY_CHECKING": "False",
                    },
                )
                # Capture ansible stdout artifact into the per-run log file (thread-safe:
                # each call has its own log_path, so no shared file handle or sys.stdout mutation)
                stdout_path = path.join(run_tmp, "artifacts", ansible_result.config.ident, "stdout")
                if path.exists(stdout_path):
                    with open(log_path, "a") as f:
                        with open(stdout_path) as af:
                            f.write(af.read())
            if ansible_result.status == "successful":
                break
            time.sleep(5)

        if ansible_result is None or ansible_result.status != "successful":
            raise Exception(f"Playbook {playbook.name} failed")

        return ansible_result

    def run_playbooks(self, playbooks: list[AnsiblePlaybook], run_async=True):
        if run_async:
            self.run_playbooks_async(playbooks)
        else:
            self.run_playbooks_serial(playbooks)

    def run_playbooks_serial(self, playbooks: list[AnsiblePlaybook]):
        for playbook in playbooks:
            self.run_playbook(playbook)

    def run_playbooks_async(self, playbooks: list[AnsiblePlaybook]):
        log_path = path.join(self.log_path, "ansible_log.log")
        remaining = list(playbooks)

        for attempt in range(self.MAX_RETRIES):
            if not remaining:
                break
            failed = []
            with open(log_path, "a") as f:
                with redirect_stdout(f):
                    for i in range(0, len(remaining), 10):
                        jobs = []
                        for playbook in remaining[i : i + 10]:
                            playbook_full_params = (
                                self.ansible_vars_default | playbook.params
                            )
                            thread, runner = ansible_runner.run_async(
                                extravars=playbook_full_params,
                                private_data_dir=self._runner_tmp.name,
                                project_dir=path.abspath(self.ansible_dir),
                                inventory=path.abspath(path.join(self.ansible_dir, "inventory")),
                                playbook=playbook.name,
                                quiet=False,
                            )
                            jobs.append((playbook, thread, runner))

                        for _, thread, _ in jobs:
                            thread.join()

                        for playbook, _, runner in jobs:
                            if runner.status != "successful":
                                failed.append(playbook)

            remaining = failed
            if remaining and attempt < self.MAX_RETRIES - 1:
                time.sleep(5)

        if remaining:
            raise Exception(f"Playbook failed after {self.MAX_RETRIES} attempts")

    def update_management_ip(self, new_ip):
        self.management_ip = new_ip
        self.ansible_vars_default["manage_ip"] = new_ip
