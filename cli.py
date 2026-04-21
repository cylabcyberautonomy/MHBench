from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from config.config import Config
from src.compilation.compiler_service import CompilerService
from src.compilation.offline_registry_service import OfflineRegistryService
from src.deployment.online_registry_service import OnlineRegistryService
from src.deployment.orchestrator import DeploymentOrchestrator
from src.deployment.openstack_client import build_connection
from src.deployment.spec_parsers import JsonSpecParser
from src.playbooks.playbook_registry_service import PlaybookRegistryService

_CONFIG_PATH = Path("config/config.yaml")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s", level=level)


def _load_config(config_path: Path) -> Config:
    if not config_path.exists():
        raise click.ClickException(f"Config file not found: {config_path}")
    return Config.load(config_path)


@click.group()
@click.option("--config", "config_path", default=str(_CONFIG_PATH), show_default=True,
              type=click.Path(path_type=Path), help="Path to config.yaml")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx: click.Context, config_path: Path, verbose: bool) -> None:
    """MHBench v3 — multi-host cybersecurity benchmark CLI."""
    _setup_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path


# ---------------------------------------------------------------------------
# compile
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("images", nargs=-1)
@click.option("--all", "compile_all", is_flag=True, help="Compile every non-root image in the offline registry")
@click.option("--force", is_flag=True, help="Recompile even if the output file already exists")
@click.pass_context
def compile(ctx: click.Context, images: tuple[str, ...], compile_all: bool, force: bool) -> None:
    """Compile one or more offline VM images.

    IMAGES are names from the offline registry (e.g. ubuntu_base webserver).
    Pass --all to compile every non-root image in dependency order.
    """
    if not images and not compile_all:
        raise click.UsageError("Specify at least one IMAGE name or pass --all.")

    config = _load_config(ctx.obj["config_path"])
    offline = OfflineRegistryService(config)
    playbook_registry = PlaybookRegistryService(config)
    service = CompilerService(config, offline, playbook_registry)

    if compile_all:
        click.echo("Compiling all images...")
        service.compile_all(force=force)
    else:
        for name in images:
            if name not in offline.list_images():
                raise click.ClickException(
                    f"Unknown image '{name}'. Available: {', '.join(offline.list_images())}"
                )
            click.echo(f"Compiling '{name}' (with ancestors)...")
            service.compile_with_ancestors(name, force=force)

    click.echo("Done.")


# ---------------------------------------------------------------------------
# provision
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("spec", type=click.Path(exists=True, path_type=Path))
@click.option("--c2c-url", default=None, help="C2C server URL (e.g. http://10.0.0.1:8888); overrides config")
@click.option("--project-name", default=None, help="Prefix for all OpenStack resource names (e.g. experiment name)")
@click.option("--output-file", type=click.Path(path_type=Path), default=None,
              help="Write JSON result {mgmt_ip} to this file after provisioning")
@click.pass_context
def provision(ctx: click.Context, spec: Path, c2c_url: str | None, project_name: str | None, output_file: Path | None) -> None:
    """Provision OpenStack networks and VMs for a topology (no Ansible).

    SPEC is the path to an environment JSON (e.g. environments/dumbbell.json).
    """
    import json
    from urllib.parse import urlparse
    from config.config import C2CConfig

    config = _load_config(ctx.obj["config_path"])
    offline = OfflineRegistryService(config)
    online = OnlineRegistryService(config)
    parser = JsonSpecParser()

    click.echo(f"Parsing spec: {spec}")
    topology = parser.parse(spec)

    errors = parser.validate(topology, offline, online)
    if errors:
        for err in errors:
            click.echo(f"  ERROR: {err}", err=True)
        raise click.ClickException("Spec validation failed.")

    if config.openstack is None:
        raise click.ClickException("openstack config block is required for provisioning.")

    if c2c_url:
        parsed = urlparse(c2c_url)
        config.c2c = C2CConfig(ip=parsed.hostname, port=parsed.port or 8888)

    playbook_registry = PlaybookRegistryService(config)
    conn = build_connection(config.openstack)
    orchestrator = DeploymentOrchestrator(conn, config, online, playbook_registry, project_name=project_name)

    click.echo(f"Provisioning topology '{topology.name}'...")
    mgmt_floating_ip = orchestrator.provision(topology)
    click.echo("Provisioning complete.")

    if output_file:
        output_file.write_text(json.dumps({"mgmt_ip": mgmt_floating_ip}))


# ---------------------------------------------------------------------------
# configure
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("spec", type=click.Path(exists=True, path_type=Path))
@click.option("--mgmt-ip", default=None, help="Management host floating IP (from provisioning)")
@click.option("--c2c-url", default=None, help="C2C server URL (e.g. http://10.0.0.1:8888); overrides config")
@click.option("--project-name", default=None, help="Prefix used during provisioning")
@click.pass_context
def configure(ctx: click.Context, spec: Path, mgmt_ip: str | None, c2c_url: str | None, project_name: str | None) -> None:
    """Run Ansible playbooks against a provisioned topology.

    SPEC is the same environment JSON used to provision.
    """
    from urllib.parse import urlparse
    from config.config import C2CConfig

    config = _load_config(ctx.obj["config_path"])
    online = OnlineRegistryService(config)
    parser = JsonSpecParser()

    click.echo(f"Parsing spec: {spec}")
    topology = parser.parse(spec)

    if config.openstack is None:
        raise click.ClickException("openstack config block is required for configuration.")

    if c2c_url:
        parsed = urlparse(c2c_url)
        config.c2c = C2CConfig(ip=parsed.hostname, port=parsed.port or 8888)

    playbook_registry = PlaybookRegistryService(config)
    conn = build_connection(config.openstack)
    orchestrator = DeploymentOrchestrator(conn, config, online, playbook_registry, project_name=project_name)

    click.echo(f"Configuring topology '{topology.name}'...")
    orchestrator.configure(topology, mgmt_ip)
    click.echo("Configuration complete.")


# ---------------------------------------------------------------------------
# deploy
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("spec", type=click.Path(exists=True, path_type=Path))
@click.option("--validate-only", is_flag=True, help="Parse and validate the spec without deploying")
@click.option("--c2c-url", default=None, help="C2C server URL (e.g. http://10.0.0.1:8888); overrides config")
@click.option("--project-name", default=None, help="Prefix for all OpenStack resource names (e.g. experiment name)")
@click.pass_context
def deploy(ctx: click.Context, spec: Path, validate_only: bool, c2c_url: str | None, project_name: str | None) -> None:
    """Deploy a network topology from a JSON spec file.

    SPEC is the path to an environment JSON (e.g. environments/dumbbell.json).
    """
    from urllib.parse import urlparse
    from config.config import C2CConfig

    config = _load_config(ctx.obj["config_path"])
    offline = OfflineRegistryService(config)
    online = OnlineRegistryService(config)
    parser = JsonSpecParser()

    click.echo(f"Parsing spec: {spec}")
    topology = parser.parse(spec)

    errors = parser.validate(topology, offline, online)
    if errors:
        for err in errors:
            click.echo(f"  ERROR: {err}", err=True)
        raise click.ClickException("Spec validation failed.")

    if validate_only:
        click.echo("Validation passed.")
        return

    if config.openstack is None:
        raise click.ClickException("openstack config block is required for deployment.")

    if c2c_url:
        parsed = urlparse(c2c_url)
        config.c2c = C2CConfig(ip=parsed.hostname, port=parsed.port or 8888)

    playbook_registry = PlaybookRegistryService(config)
    conn = build_connection(config.openstack)
    orchestrator = DeploymentOrchestrator(conn, config, online, playbook_registry, project_name=project_name)

    click.echo(f"Deploying topology '{topology.name}'...")
    orchestrator.deploy(topology)
    click.echo("Deployment complete.")


# ---------------------------------------------------------------------------
# teardown
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("spec", type=click.Path(exists=True, path_type=Path))
@click.option("--yes", is_flag=True, help="Skip confirmation prompt")
@click.option("--project-name", default=None, help="Prefix used when deploying (must match the deploy --project-name)")
@click.pass_context
def teardown(ctx: click.Context, spec: Path, yes: bool, project_name: str | None) -> None:
    """Tear down a previously deployed topology.

    SPEC is the same environment JSON used to deploy (e.g. environments/dumbbell.json).
    """
    config = _load_config(ctx.obj["config_path"])
    parser = JsonSpecParser()

    click.echo(f"Parsing spec: {spec}")
    topology = parser.parse(spec)

    if not yes:
        click.confirm(
            f"This will delete all resources for topology '{topology.name}'. Continue?",
            abort=True,
        )

    if config.openstack is None:
        raise click.ClickException("openstack config block is required for teardown.")

    online = OnlineRegistryService(config)
    playbook_registry = PlaybookRegistryService(config)
    conn = build_connection(config.openstack)
    orchestrator = DeploymentOrchestrator(conn, config, online, playbook_registry, project_name=project_name)

    click.echo(f"Tearing down topology '{topology.name}'...")
    orchestrator.teardown(topology)
    click.echo("Teardown complete.")


if __name__ == "__main__":
    cli()
