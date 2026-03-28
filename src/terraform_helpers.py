import json
import os
import subprocess
import tempfile
from contextlib import contextmanager
from typing import Iterator

from config.config import Config


def _clean_env() -> dict:
    """Return os.environ with all OS_* variables stripped so Terraform uses only provider-block values."""
    return {k: v for k, v in os.environ.items() if not k.startswith("OS_")}


@contextmanager
def _temporary_tfvars(config: Config) -> Iterator[str]:
    """Create a throwaway tfvars file for Terraform and clean it up afterwards."""
    terraform_vars = config.terraform_vars
    tfvars_content = "\n".join(
        f"{key} = {json.dumps(value)}" for key, value in terraform_vars.items()
    )

    tmp_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".tfvars", delete=False, encoding="utf-8"
    )
    try:
        tmp_file.write(tfvars_content)
        tmp_file.flush()
        tmp_file.close()
        yield tmp_file.name
    finally:
        try:
            os.remove(tmp_file.name)
        except OSError:
            pass


def deploy_network(name: str, config: Config) -> None:
    deployment_dir = os.path.join("src/environments/terraform/topologies", name)
    subprocess.run(
        ["terraform", "init"],
        cwd=deployment_dir,
        capture_output=True,
        text=True,
        env=_clean_env(),
    )

    # Use a per-project state file via -state= instead of workspaces.
    # Workspaces store the selected workspace in .terraform/environment (a file
    # in the shared topology directory), which causes a race when multiple
    # processes compile in parallel — they all overwrite each other's selection
    # and end up locking the same state file.  With -state=, each project gets
    # its own state file path and the shared directory is never mutated.
    project_name = config.openstack_config.project_name
    state_dir = os.path.abspath(os.path.join(".terraform_states", project_name))
    os.makedirs(state_dir, exist_ok=True)
    state_file = os.path.join(state_dir, f"{name}.tfstate")

    log_dir = os.path.abspath(os.path.join(".terraform_states", project_name))
    tf_log_file = os.path.join(log_dir, f"{name}_terraform.log")

    with _temporary_tfvars(config) as tfvars_path:
        # Destroy first so Terraform state is clean before recreating.
        # The OpenStack resources are already gone (deleted by teardown_helper
        # before deploy_network is called), but the state file still references
        # their old IDs. Destroying explicitly reconciles the state.
        with open(tf_log_file, "a") as log:
            log.write(f"\n=== terraform destroy ===\n")
            proc = subprocess.Popen(
                [
                    "terraform", "destroy",
                    f"-state={state_file}",
                    f"-var-file={tfvars_path}",
                    "-auto-approve",
                ],
                cwd=deployment_dir,
                stdout=log,
                stderr=log,
                universal_newlines=True,
                env=_clean_env(),
            )
            proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(
                    f"terraform destroy failed (exit {proc.returncode}). "
                    f"See {tf_log_file} for details."
                )

            log.write(f"\n=== terraform apply ===\n")
            proc = subprocess.Popen(
                [
                    "terraform", "apply",
                    f"-state={state_file}",
                    f"-var-file={tfvars_path}",
                    "-auto-approve",
                    "-parallelism=3",
                ],
                cwd=deployment_dir,
                stdout=log,
                stderr=log,
                universal_newlines=True,
                env=_clean_env(),
            )
            proc.communicate()
            if proc.returncode != 0:
                raise RuntimeError(
                    f"terraform apply failed (exit {proc.returncode}). "
                    f"See {tf_log_file} for details."
                )


def destroy_network(name: str, config: Config) -> None:
    deployment_dir = os.path.join("src/environments/terraform/topologies", name)
    subprocess.run(
        ["terraform", "init"],
        cwd=deployment_dir,
        capture_output=True,
        text=True,
        env=_clean_env(),
    )

    project_name = config.openstack_config.project_name
    state_file = os.path.abspath(
        os.path.join(".terraform_states", project_name, f"{name}.tfstate")
    )

    with _temporary_tfvars(config) as tfvars_path:
        subprocess.Popen(
            [
                "terraform", "destroy",
                f"-state={state_file}",
                f"-var-file={tfvars_path}",
                "-auto-approve",
            ],
            cwd=deployment_dir,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            env=_clean_env(),
        ).communicate()
