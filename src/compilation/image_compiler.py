from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class ImageCompiler:

    def compile(self, base_image: Path, playbooks: list[Path], output_path: Path) -> None:
        if not playbooks:
            shutil.copy2(base_image, output_path)
            return

        tmp = output_path.with_suffix(".qcow2.tmp")
        tmp.unlink(missing_ok=True)
        shutil.copy2(base_image, tmp)

        try:
            with tempfile.TemporaryDirectory(prefix="mhbench-") as workdir:
                mount_dir = Path(workdir) / "root"
                mount_dir.mkdir()
                subprocess.run(["guestmount", "-a", str(tmp), "-i", "--rw", str(mount_dir)], check=True)
                try:
                    ansible_tmp_dir = Path(workdir) / "ansible-tmp"
                    ansible_tmp_dir.mkdir(mode=0o1777)
                    chroot_wrapper = Path(workdir) / "proot-chroot"
                    chroot_wrapper.write_text(
                        "#!/bin/sh\nrootdir=\"$1\"; shift\n"
                        f"tmpdir=\"{ansible_tmp_dir}\"\n"
                        "chmod 1777 \"$tmpdir\"\n"
                        "exec proot -R \"$rootdir\" -b \"$tmpdir:/tmp\" -0 \"$@\"\n"
                    )
                    chroot_wrapper.chmod(0o755)

                    inventory_file = Path(workdir) / "inventory.yml"
                    inventory_file.write_text(
                        "all:\n"
                        "  hosts:\n"
                        f"    {mount_dir}:\n"
                        "      ansible_connection: chroot\n"
                        f"      ansible_chroot_exe: {chroot_wrapper}\n"
                        "      ansible_chroot_disable_root_check: true\n"
                        "      ansible_remote_tmp: /tmp\n"
                    )

                    for pb in playbooks:
                        env = os.environ.copy()
                        env["ANSIBLE_REMOTE_TEMP"] = "/tmp"
                        env["ANSIBLE_GATHERING"] = "explicit"

                        cmd = [
                            "ansible-playbook",
                            "-v",
                            "-i",
                            str(inventory_file),
                            "-e",
                            f"host={mount_dir}",
                            str(pb.resolve()),
                        ]
                        logger.info("[COMPILER] Running playbook '%s'.", pb.name)
                        proc = subprocess.Popen(
                            cmd,
                            cwd=workdir,
                            env=env,
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                        )

                        output_lines: list[str] = []
                        assert proc.stdout is not None
                        for line in proc.stdout:
                            output_lines.append(line)
                            logger.info(line.rstrip("\n"))

                        rc = proc.wait()
                        if rc != 0:
                            logger.error("ansible-playbook rc: %s", rc)
                            raise RuntimeError(f"Playbook '{pb.name}' failed (rc: {rc}).")
                finally:
                    subprocess.run(["guestunmount", str(mount_dir)], check=False)
            tmp.rename(output_path)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
