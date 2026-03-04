import click
import importlib
import openstack
from datetime import datetime
import os
import time
from types import SimpleNamespace

from config.config_service import ConfigService
from src.terraform_deployer import TerraformDeployer
from src.env_gen_deployer import EnvGenDeployer
from src.webhook_notifier import WebhookNotifier
from ansible.ansible_runner import AnsibleRunner
from src.models.network import NetworkTopology
import json


env_module = importlib.import_module("src.environments.terraform.specifications")


def create_openstack_connection(openstack_cfg):
    """
    Build an OpenStack connection directly from the app config instead of
    relying on a clouds.yml entry.
    """
    return openstack.connect(
        auth_url=openstack_cfg.openstack_auth_url,
        username=openstack_cfg.openstack_username,
        password=openstack_cfg.openstack_password,
        project_name=openstack_cfg.project_name,
        region_name=openstack_cfg.openstack_region,
        user_domain_name="Default",
        project_domain_name="Default",
    )


def _make_notifier(config) -> WebhookNotifier | None:
    if config.webhook_config:
        return WebhookNotifier(config.webhook_config.url, config.webhook_config.type)
    return None


@click.group()
@click.option(
    "--type",
    help="The environment (class name or generated JSON file name)",
    required=True,
    type=str,
)
@click.option(
    "--config-file",
    help="Path to the MHBench configuration JSON",
    default="config/config.json",
    show_default=True,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
)
@click.pass_context
def env(ctx, type: str, config_file: str):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    experiment_dir = f"./output/misc/{timestamp}"
    # Create the experiment directory
    os.makedirs(experiment_dir, exist_ok=True)

    ctx.ensure_object(SimpleNamespace)
    config = ConfigService(config_file).get_config()
    ctx.obj.config = config
    ctx.obj.config_path = config_file
    ctx.obj.env_type = type

    openstack_conn = create_openstack_connection(config.openstack_config)
    ssh_key_path = os.path.expanduser(config.openstack_config.ssh_key_path)
    ansible_runner = AnsibleRunner(
        ssh_key_path,
        None,
        "./ansible/",
        experiment_dir,
        False,
    )

    # Try to load as a specification class first
    environment: TerraformDeployer | None = None
    topology: NetworkTopology | None = None
    orchestrator: EnvGenDeployer | None = None
    try:
        env_instance_class = getattr(env_module, type)
        environment = env_instance_class(
            ansible_runner,
            openstack_conn,
            ctx.obj.config.external_ip,
            ctx.obj.config,
        )
        click.echo(f"Loaded specification-based environment: {type}")
    except AttributeError:
        # Check if it's a path or just a name
        if type.endswith(".json") or "/" in type:
            json_file = type
        else:
            # Try common patterns for generated environments
            json_file = type

        try:
            env_path = os.path.join("src/environments/generated/", type + ".json")
            with open(env_path, "r") as f:
                data = json.load(f)
                topology = NetworkTopology(**data)
                click.echo(f"Loaded generated environment from: {json_file}")
        except FileNotFoundError as e:
            click.echo(f"Error: Could not find environment '{env_path}'", err=True)
            ctx.exit(1)

        orchestrator = EnvGenDeployer(config, openstack_conn)

    ctx.obj.environment = environment
    ctx.obj.orchestrator = orchestrator
    ctx.obj.topology = topology


@env.command()
@click.pass_context
@click.option("--skip_network", help="Skip network setup", is_flag=True)
def setup(ctx, skip_network: bool):
    notifier = _make_notifier(ctx.obj.config)
    env_type = ctx.obj.env_type
    if notifier:
        notifier.notify_start("setup", env_type)
    start = time.time()
    try:
        click.echo("Setting up the environment...")
        if skip_network:
            click.echo("Skipping network setup")
            ctx.obj.environment.find_management_server()
            ctx.obj.environment.parse_network()
            ctx.obj.environment.runtime_setup()
        else:
            ctx.obj.environment.deploy_topology()
            ctx.obj.environment.setup()
            ctx.obj.environment.runtime_setup()
        if notifier:
            notifier.notify_success("setup", env_type, time.time() - start)
    except Exception as exc:
        if notifier:
            notifier.notify_error("setup", env_type, time.time() - start, exc)
        raise


@env.command()
@click.pass_context
@click.option("--skip_network", help="Skip network setup", is_flag=True)
@click.option("--skip_host", help="Skip host setup", is_flag=True)
def compile(ctx, skip_network: bool, skip_host: bool):
    notifier = _make_notifier(ctx.obj.config)
    env_type = ctx.obj.env_type
    if notifier:
        notifier.notify_start("compile", env_type)
    start = time.time()
    try:
        click.echo("Compiling the environment (can take several hours)...")
        if ctx.obj.environment is not None:
            ctx.obj.environment.compile(not skip_network, not skip_host)
        else:
            ctx.obj.orchestrator.compile_environment(ctx.obj.topology)
        if notifier:
            notifier.notify_success("compile", env_type, time.time() - start)
    except Exception as exc:
        if notifier:
            notifier.notify_error("compile", env_type, time.time() - start, exc)
        raise


@env.command()
@click.pass_context
def teardown(ctx):
    notifier = _make_notifier(ctx.obj.config)
    env_type = ctx.obj.env_type
    if notifier:
        notifier.notify_start("teardown", env_type)
    start = time.time()
    try:
        click.echo("Tearing down the environment...")
        if ctx.obj.environment is not None:
            ctx.obj.environment.teardown()
        else:
            ctx.obj.orchestrator.cleaner.clean_environment()
        click.echo("Environment has been torn down")
        if notifier:
            notifier.notify_success("teardown", env_type, time.time() - start)
    except Exception as exc:
        if notifier:
            notifier.notify_error("teardown", env_type, time.time() - start, exc)
        raise


@env.command()
@click.pass_context
def deploy_network(ctx):
    click.echo("Setting up network...")
    if ctx.obj.environment is not None:
        ctx.obj.environment.deploy_topology()
    else:
        ctx.obj.orchestrator.deploy_environment(ctx.obj.topology)


if __name__ == "__main__":
    # Entrypoint for the CLI
    env()
