"""
MHBench DSL CLI

Deploy topology-YAML-defined environments directly to OpenStack.

Usage:
    uv run python dsl.py --type equifax_small compile [--skip-bake]
    uv run python dsl.py --type equifax_small deploy
    uv run python dsl.py --type equifax_small teardown

--type looks for topologies/{type}.yaml.

compile   Bake role-specific images, deploy networks + hosts, run setup playbooks.
          Use --skip-bake when images (e.g. mhbench_webserver_baked) already exist
          in Glance to skip the slow baking step.

deploy    Deploy from baked images and run setup playbooks (skips baking).

teardown  Tear down all OpenStack resources created by this project.
"""

import os
import signal
from types import SimpleNamespace

import click
import openstack
import psutil

from config.config_service import ConfigService
from src.dsl.deployer import DSLDeployer
from src.dsl.topology.schema import TopologySpec
from src.image_baker import VmBakeSpec


def _kill_children(signum, frame):
    try:
        me = psutil.Process()
        for child in me.children(recursive=True):
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
    except Exception:
        pass
    raise SystemExit(1)


signal.signal(signal.SIGTERM, _kill_children)
signal.signal(signal.SIGINT, _kill_children)


def _openstack_connection(cfg):
    return openstack.connect(
        auth_url=cfg.openstack_auth_url,
        username=cfg.openstack_username,
        password=cfg.openstack_password,
        project_name=cfg.project_name,
        region_name=cfg.openstack_region,
        user_domain_name="Default",
        project_domain_name="Default",
    )


def _bake_specs_from_spec(spec: TopologySpec) -> list[VmBakeSpec]:
    """Build minimal bake_specs from the vm_types referenced in the topology.

    Follows the mhbench_{type}_baked naming convention already in Glance.
    Replace this with VmTypeRegistry.bake_specs() once the registry is ready.
    """
    vm_types = {
        group.vm_type
        for network in spec.networks
        for subnet in network.subnets
        for group in subnet.host_groups
    }
    return [
        VmBakeSpec(
            type_name=t,
            base_image_name="",        # unused when skipping bake
            bake_playbooks=[],         # unused when skipping bake
            baked_image_name=f"mhbench_{t}_baked",
            flavor_name="m1.small",    # placeholder; replace via VmTypeRegistry
        )
        for t in vm_types
    ]


@click.group()
@click.option(
    "--type",
    required=True,
    help="Topology name — looks up topologies/{type}.yaml",
)
@click.option(
    "--config-file",
    default="config/config.json",
    show_default=True,
    type=click.Path(dir_okay=False),
)
@click.pass_context
def dsl(ctx, type: str, config_file: str):
    ctx.ensure_object(SimpleNamespace)

    topology_path = os.path.join("topologies", f"{type}.yaml")
    if not os.path.exists(topology_path):
        raise click.ClickException(f"Topology file not found: {topology_path}")

    config = ConfigService(config_file).get_config()
    conn = _openstack_connection(config.openstack_config)

    ctx.obj.spec = TopologySpec.from_yaml(topology_path)
    ctx.obj.deployer = DSLDeployer(config, conn)

    click.echo(f"Loaded topology: {topology_path}")


@dsl.command()
@click.option(
    "--skip-bake",
    is_flag=True,
    default=False,
    help="Skip image baking — use when baked images already exist in Glance.",
)
@click.pass_context
def compile(ctx, skip_bake: bool):
    """Bake images, deploy networks + hosts, run host setup playbooks."""
    spec = ctx.obj.spec
    deployer = ctx.obj.deployer

    # TODO: replace with VmTypeRegistry once the registry is ready:
    #   registry = VmTypeRegistry.from_yaml(f"vm_types/{spec.name}_types.yaml")
    #   bake_specs = registry.bake_specs()
    #   setup_factories = registry.setup_factories()
    bake_specs = _bake_specs_from_spec(spec)
    setup_factories: dict = {}

    if skip_bake:
        click.echo("Skipping image baking (--skip-bake set).")
        deployer.deploy(spec, bake_specs, setup_factories)
    else:
        deployer.compile(spec, bake_specs, setup_factories)

    click.echo("Compile complete.")


@dsl.command()
@click.pass_context
def deploy(ctx):
    """Deploy from baked images and run setup playbooks (skips baking)."""
    spec = ctx.obj.spec
    bake_specs = _bake_specs_from_spec(spec)
    setup_factories: dict = {}

    click.echo("Deploying...")
    ctx.obj.deployer.deploy(spec, bake_specs, setup_factories)
    click.echo("Deploy complete.")


@dsl.command()
@click.pass_context
def teardown(ctx):
    """Remove all OpenStack resources created by this project."""
    click.echo("Tearing down environment...")
    ctx.obj.deployer.cleaner.clean_environment()
    click.echo("Teardown complete.")


if __name__ == "__main__":
    dsl()
