from __future__ import annotations

import logging
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import ansible_runner

logger = logging.getLogger(__name__)

_SSH_OPTS = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
_CLEANUP_AND_SHUTDOWN = """\
cloud-init clean --logs 2>/dev/null || true
apt-get clean 2>/dev/null || true
rm -rf /var/lib/apt/lists/* 2>/dev/null || true
rm -f /etc/ssh/ssh_host_* 2>/dev/null || true
truncate -s 0 /etc/machine-id 2>/dev/null || true
rm -f /var/lib/dbus/machine-id 2>/dev/null || true
shutdown -h now
"""


def compile_image(base_image: Path, playbooks: list[Path], output_path: Path, disk_size_gb: int | None = None) -> None:
    tmp = output_path.with_suffix(".qcow2.tmp")
    tmp.unlink(missing_ok=True)
    shutil.copy2(base_image, tmp)
    if disk_size_gb is not None:
        subprocess.run(["qemu-img", "resize", str(tmp), f"{disk_size_gb}G"], check=True, capture_output=True)

    workdir = Path(tempfile.mkdtemp(prefix="mhbench-"))
    proc = None
    try:
        # Generate ephemeral SSH keypair
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(workdir / "key")],
            check=True, capture_output=True,
        )
        pub_key = (workdir / "key.pub").read_text().strip()

        # Cloud-init seed ISO
        (workdir / "user-data").write_text(f"""\
#cloud-config
disable_root: false
package_update: false
runcmd:
  - mkdir -p /root/.ssh
  - echo '{pub_key}' >> /root/.ssh/authorized_keys
  - chmod 700 /root/.ssh
  - chmod 600 /root/.ssh/authorized_keys
  - touch /tmp/cloud-init-done
""")
        (workdir / "meta-data").write_text(f"instance-id: compile-{int(time.time())}\nlocal-hostname: compile-vm\n")
        subprocess.run(
            ["genisoimage", "-output", str(workdir / "seed.iso"),
             "-volid", "cidata", "-joliet", "-rock",
             str(workdir / "user-data"), str(workdir / "meta-data")],
            check=True, capture_output=True,
        )

        # Find a free port and boot the VM
        with socket.socket() as s:
            s.bind(("", 0))
            ssh_port = s.getsockname()[1]

        kvm = ["-enable-kvm"] if Path("/dev/kvm").exists() else []
        if not kvm:
            logger.warning("KVM not available — VM will run slowly.")
        proc = subprocess.Popen(
            ["qemu-system-x86_64", *kvm, "-m", "2048", "-smp", "2",
             "-drive", f"file={tmp},format=qcow2,if=virtio",
             "-drive", f"file={workdir / 'seed.iso'},format=raw,if=virtio",
             "-netdev", f"user,id=net0,hostfwd=tcp::{ssh_port}-:22",
             "-device", "virtio-net-pci,netdev=net0",
             "-display", "none"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        # Wait for SSH port to accept connections
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", ssh_port), timeout=5).close()
                break
            except OSError:
                time.sleep(5)
        else:
            raise TimeoutError(f"SSH port {ssh_port} did not open within 300s.")

        # Wait for cloud-init to finish
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            result = subprocess.run(
                ["ssh", *_SSH_OPTS.split(), "-i", str(workdir / "key"),
                 "-p", str(ssh_port), "root@127.0.0.1",
                 "test -f /tmp/cloud-init-done"],
                capture_output=True,
            )
            if result.returncode == 0:
                break
            time.sleep(5)
        else:
            raise TimeoutError("Cloud-init did not complete within 120s.")

        # Run playbooks
        (workdir / "project").symlink_to(playbooks[0].parent.resolve())
        inventory = {"all": {"hosts": {"bake_target": {
            "ansible_host": "127.0.0.1",
            "ansible_port": ssh_port,
            "ansible_user": "root",
            "ansible_ssh_private_key_file": str(workdir / "key"),
            "ansible_ssh_common_args": _SSH_OPTS,
        }}}}
        for pb in playbooks:
            logger.info("Running playbook: %s", pb.name)
            result = ansible_runner.run(
                private_data_dir=str(workdir),
                playbook=pb.name,
                inventory=inventory,
                extravars={"host": "bake_target"},
            )
            if result.status != "successful":
                stderr = result.stderr.read() if result.stderr else ""
                raise RuntimeError(
                    f"Playbook '{pb.name}' failed (status: {result.status}).\n{stderr}"
                )

        # Clean up VM internals and shut down
        subprocess.run(
            ["ssh", *_SSH_OPTS.split(), "-i", str(workdir / "key"),
             "-p", str(ssh_port), "root@127.0.0.1", _CLEANUP_AND_SHUTDOWN],
            capture_output=True,
        )
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            logger.warning("VM did not shut down cleanly — force-killing.")
            proc.kill()
            proc.wait()

    except Exception:
        if proc:
            proc.kill()
            proc.wait()
        tmp.unlink(missing_ok=True)
        shutil.rmtree(workdir, ignore_errors=True)
        raise

    shutil.rmtree(workdir, ignore_errors=True)
    tmp.rename(output_path)
    logger.info("Compiled: %s", output_path)
