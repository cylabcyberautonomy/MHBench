"""
image_baker.py — Bake per-VM-type qcow2 images using bake-image.sh.

Each VmBakeSpec describes one logical VM type (e.g. "webserver", "database",
"attacker").  ImageBaker checks whether the baked image already exists in
OpenStack Glance and, if not, downloads the base image, runs bake-image.sh
with the designated Ansible playbooks chained together, then uploads the
result back to Glance.

The baked image is later referenced by name in Terraform so that every VM of
that type boots with all static software pre-installed.  Dynamic, inter-VM
configuration (SSH-key exchange, data seeding, etc.) is deferred to the
environment's compile_setup() which is called at setup time.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Callable

from openstack.connection import Connection
from src.legacy_models.network import Host
from ansible.ansible_playbook import AnsiblePlaybook
from src.utility.logging import get_logger

logger = get_logger()

# Path to bake-image.sh relative to the MHBench project root.
_BAKE_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "bake-image.sh")


@dataclass
class VmBakeSpec:
    """Describes how to bake one VM type and what to run on it at setup time.

    Attributes:
        type_name:
            Short identifier used in log messages and for matching hosts by
            name prefix, e.g. "webserver".
        base_image_name:
            Name of the OpenStack Glance image to use as the starting point,
            e.g. "Ubuntu24" or "Kali".
        bake_playbooks:
            Ordered list of Ansible playbook paths (relative to the MHBench
            project root) to run during baking, e.g.:
              ["ansible/bake_playbooks/ubuntu_base.yml",
               "ansible/bake_playbooks/webserver.yml"]
            All playbooks are combined into a single bake-image.sh invocation
            so the VM boots only once.
        baked_image_name:
            Name under which the finished image is stored in OpenStack Glance,
            e.g. "mhbench_webserver_baked".
        bake_extra_vars:
            Extra Ansible variables forwarded to bake-image.sh via -e, e.g.
            {"es_address": "https://10.0.0.1:9200", "es_password": "secret"}.
        setup_playbook_factories:
            List of callables that each accept a Host and return an
            AnsiblePlaybook (or None to skip).  Called at setup time by
            TerraformDeployer._run_host_setup_playbooks() for every live host
            whose name starts with type_name.
    """

    type_name: str
    base_image_name: str
    bake_playbooks: list[str]
    baked_image_name: str
    bake_extra_vars: dict[str, str] = field(default_factory=dict)
    setup_playbook_factories: list[Callable[[Host], AnsiblePlaybook | None]] = field(
        default_factory=list
    )


class ImageBaker:
    """Orchestrates per-type image baking against OpenStack Glance.

    Downloads the base image from Glance, runs bake-image.sh (which boots a
    temporary QEMU/KVM VM, applies one or more Ansible playbooks in sequence,
    then shuts down so the qcow2 is in a clean final state), and uploads the
    result back to Glance under the baked image name.
    """

    def __init__(
        self,
        openstack_conn: Connection,
        bake_script: str = _BAKE_SCRIPT,
    ) -> None:
        self.openstack_conn = openstack_conn
        self.bake_script = bake_script

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_baked(self, spec: VmBakeSpec) -> bool:
        """Return True if the baked image already exists and is active."""
        image = self.openstack_conn.get_image(spec.baked_image_name)
        return image is not None and image.status == "active"

    def bake(self, spec: VmBakeSpec) -> None:
        """Bake *spec* if its image does not yet exist in Glance."""
        if self.is_baked(spec):
            logger.info(
                f"[BAKE] {spec.type_name}: image '{spec.baked_image_name}' "
                "already exists — skipping."
            )
            return

        logger.info(
            f"[BAKE] {spec.type_name}: starting bake "
            f"(base='{spec.base_image_name}', "
            f"playbooks={spec.bake_playbooks}) ..."
        )

        with tempfile.TemporaryDirectory(prefix="mhbench-bake-") as workdir:
            qcow2_path = os.path.join(workdir, f"{spec.type_name}.qcow2")
            combined_playbook = os.path.join(workdir, "combined.yml")

            self._download_image(spec.base_image_name, qcow2_path)
            self._write_combined_playbook(spec.bake_playbooks, combined_playbook)
            self._run_bake_script(spec, qcow2_path, combined_playbook)
            self._upload_image(spec.baked_image_name, qcow2_path)

        logger.info(
            f"[BAKE] {spec.type_name}: uploaded as '{spec.baked_image_name}'."
        )

    def bake_all(self, specs: list[VmBakeSpec]) -> None:
        """Bake every spec in *specs*, skipping those already present."""
        for spec in specs:
            self.bake(spec)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _download_image(self, image_name: str, dest_path: str) -> None:
        """Download *image_name* from Glance into *dest_path* as raw bytes."""
        image = self.openstack_conn.get_image(image_name)
        if image is None:
            raise RuntimeError(
                f"[BAKE] Base image '{image_name}' not found in OpenStack Glance."
            )

        logger.info(f"[BAKE] Downloading base image '{image_name}' ...")
        with open(dest_path, "wb") as fh:
            for chunk in self.openstack_conn.image.download_image(image.id):
                fh.write(chunk)
        logger.info(f"[BAKE] Download complete → {dest_path}")

    def _write_combined_playbook(
        self, playbook_paths: list[str], dest: str
    ) -> None:
        """Write a master playbook that import_playbook-chains all *playbook_paths*.

        Each path is resolved to an absolute path so that ansible-playbook can
        locate it regardless of the working directory that bake-image.sh uses.
        """
        project_root = os.path.dirname(os.path.dirname(__file__))
        lines = ["---"]
        for pb in playbook_paths:
            abs_path = (
                pb if os.path.isabs(pb) else os.path.join(project_root, pb)
            )
            lines.append(f"- import_playbook: {abs_path}")

        with open(dest, "w") as fh:
            fh.write("\n".join(lines) + "\n")

    def _run_bake_script(
        self, spec: VmBakeSpec, qcow2_path: str, playbook_path: str
    ) -> None:
        """Invoke bake-image.sh for *spec* against *qcow2_path*."""
        cmd = [self.bake_script, qcow2_path, playbook_path]

        # Always resolve {{ host }} to the bake_target inventory group so that
        # existing playbooks that use `hosts: "{{ host }}"` work unchanged.
        extra_vars: dict[str, str] = {"host": "bake_target", **spec.bake_extra_vars}
        for key, value in extra_vars.items():
            cmd += ["-e", f"{key}={value}"]

        logger.info(f"[BAKE] Running: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)

    def _upload_image(self, image_name: str, qcow2_path: str) -> None:
        """Upload the baked qcow2 to Glance under *image_name*, replacing any
        existing image with that name."""
        existing = self.openstack_conn.get_image(image_name)
        if existing:
            logger.info(
                f"[BAKE] Replacing existing Glance image '{image_name}' ..."
            )
            self.openstack_conn.delete_image(existing.id, wait=True)

        logger.info(f"[BAKE] Uploading '{image_name}' to Glance ...")
        self.openstack_conn.create_image(
            name=image_name,
            filename=qcow2_path,
            disk_format="qcow2",
            container_format="bare",
            wait=True,
        )
