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
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service 2>/dev/null || true
systemctl mask apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service unattended-upgrades.service 2>/dev/null || true
rm -f /etc/ssh/ssh_host_* 2>/dev/null || true
truncate -s 0 /etc/machine-id 2>/dev/null || true
rm -f /var/lib/dbus/machine-id 2>/dev/null || true
truncate -s 0 /var/log/auth.log /var/log/syslog /var/log/audit/audit.log 2>/dev/null || true
rm -f /var/log/cmdlog/* /var/log/netflow/* /root/.bash_history /home/*/.bash_history 2>/dev/null || true
rm -f /root/.ssh/authorized_keys /etc/ssh/sshd_config.d/00-compile.conf 2>/dev/null || true
shutdown -h now
"""


def compile_image(base_image: Path, playbooks: list[Path], output_path: Path, disk_size_gb: int | None = None, compress: bool = False) -> None:
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

        # Put the ephemeral key + root-login permission directly on the disk so compiler access never
        # depends on the guest's cloud-init honoring the NoCloud seed below (some cloud images use a
        # datasource that ignores it). Runs for every image; cleaned out by _CLEANUP_AND_SHUTDOWN.
        subprocess.run(
            ["virt-customize", "-a", str(tmp),
             "--ssh-inject", f"root:string:{pub_key}",
             "--run-command",
             "printf 'PermitRootLogin prohibit-password\\n' > /etc/ssh/sshd_config.d/00-compile.conf"],
            check=True, capture_output=True,
        )

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
            ["qemu-system-x86_64", *kvm, "-m", "4096", "-smp", "4",
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

        # Reachable = the injected key works. Then let cloud-init settle so playbooks don't race boot-time
        # apt jobs. Neither step depends on the guest having processed the NoCloud seed (Kali ignores it).
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if subprocess.run(
                ["ssh", *_SSH_OPTS.split(), "-o", "ConnectTimeout=10", "-i", str(workdir / "key"),
                 "-p", str(ssh_port), "root@127.0.0.1", "true"],
                capture_output=True,
            ).returncode == 0:
                break
            time.sleep(5)
        else:
            raise TimeoutError("VM did not become SSH-reachable within 600s.")
        subprocess.run(
            ["ssh", *_SSH_OPTS.split(), "-o", "ConnectTimeout=10", "-i", str(workdir / "key"),
             "-p", str(ssh_port), "root@127.0.0.1",
             "command -v cloud-init >/dev/null 2>&1 && cloud-init status --wait >/dev/null 2>&1 || true"],
            capture_output=True,
        )

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
    # convert (not rename): always compacts away the install-churn clusters qcow2 never reclaims; -c also
    # zlib-compresses (smaller/reliable upload + faster per-node cache-warm — nova decompresses once into
    # _base, so running guests read uncompressed, no deploy penalty).
    subprocess.run(["qemu-img", "convert", "-O", "qcow2", *(["-c"] if compress else []), str(tmp), str(output_path)], check=True)
    tmp.unlink(missing_ok=True)
    logger.info("Compiled: %s", output_path)
