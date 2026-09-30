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
from src.deployment.backends import build_backend
from src.deployment.spec_parsers import JsonSpecParser
from src.playbooks.playbook_registry_service import PlaybookRegistryService

_CONFIG_PATH = Path("config/config.yaml")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s", level=level)


def _require_backend_config(config) -> None:
    if config.active_backend_config() is None:
        raise click.ClickException(
            f"'{config.backend}' config block is required for this command "
            f"(set backend: {config.backend} and its config in config.yaml)."
        )


def _load_config(config_path: Path, ansible_verbosity: int = 0) -> Config:
    if not config_path.exists():
        raise click.ClickException(f"Config file not found: {config_path}")
    config = Config.load(config_path)
    config.ansible_verbosity = ansible_verbosity
    return config


@click.group()
@click.option("--config", "config_path", default=str(_CONFIG_PATH), show_default=True,
              type=click.Path(path_type=Path), help="Path to config.yaml")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.option("--ansible-verbosity", type=int, default=0, envvar="ANSIBLE_VERBOSITY",
              help="Ansible verbosity 0-4 (-vvvv); also honors $ANSIBLE_VERBOSITY")
@click.pass_context
def cli(ctx: click.Context, config_path: Path, verbose: bool, ansible_verbosity: int) -> None:
    """MHBench v3 — multi-host cybersecurity benchmark CLI."""
    _setup_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path
    ctx.obj["ansible_verbosity"] = ansible_verbosity


# ---------------------------------------------------------------------------
# compile
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("images", nargs=-1)
@click.option("--all", "compile_all", is_flag=True, help="Compile every non-root image in the offline registry")
@click.option("--force", is_flag=True, help="Recompile even if the output file already exists")
@click.option("--compress", is_flag=True, help="Also zlib-compress the output qcow2 (smaller/faster upload; compaction happens regardless)")
@click.pass_context
def compile(ctx: click.Context, images: tuple[str, ...], compile_all: bool, force: bool, compress: bool) -> None:
    """Compile one or more offline VM images.

    IMAGES are names from the offline registry (e.g. ubuntu_base webserver).
    Pass --all to compile every non-root image in dependency order.
    """
    if not images and not compile_all:
        raise click.UsageError("Specify at least one IMAGE name or pass --all.")

    config = _load_config(ctx.obj["config_path"], ctx.obj["ansible_verbosity"])
    offline = OfflineRegistryService(config)
    playbook_registry = PlaybookRegistryService(config)
    service = CompilerService(config, offline, playbook_registry)

    if compile_all:
        click.echo("Compiling all images...")
        service.compile_all(force=force, compress=compress)
    else:
        for name in images:
            if name not in offline.list_images():
                raise click.ClickException(
                    f"Unknown image '{name}'. Available: {', '.join(offline.list_images())}"
                )
            click.echo(f"Compiling '{name}' (with ancestors)...")
            service.compile_with_ancestors(name, force=force, compress=compress)

    click.echo("Done.")


# ---------------------------------------------------------------------------
# upload
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("images", nargs=-1)
@click.option("--all", "upload_all", is_flag=True, help="Upload every compiled non-root image")
@click.option("--force", is_flag=True, help="Re-upload (delete + recreate) even if already in Glance")
@click.pass_context
def upload(ctx: click.Context, images: tuple[str, ...], upload_all: bool, force: bool) -> None:
    """Push compiled images to the active backend (OpenStack Glance / GCP images).

    IMAGES are names from the offline registry (e.g. ubuntu_base webserver sensor).
    Pass --all to upload every compiled non-root image. Run after `compile`.
    """
    if not images and not upload_all:
        raise click.UsageError("Specify at least one IMAGE name or pass --all.")

    config = _load_config(ctx.obj["config_path"], ctx.obj["ansible_verbosity"])
    _require_backend_config(config)

    offline = OfflineRegistryService(config)
    online = OnlineRegistryService(config)
    backend = build_backend(config, online)

    if upload_all:
        names = [n for n in offline.list_images() if offline.get_parent(n) is not None]
    else:
        for name in images:
            if name not in offline.list_images():
                raise click.ClickException(
                    f"Unknown image '{name}'. Available: {', '.join(offline.list_images())}"
                )
        names = list(images)

    for name in names:
        click.echo(f"Uploading '{name}'...")
        backend.upload_image(name, offline.get_location(name), force=force)
    click.echo("Done.")


# ---------------------------------------------------------------------------
# provision
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("spec", type=click.Path(exists=True, path_type=Path))
@click.option("--c2c-url", default=None, help="C2C server URL (e.g. http://10.0.0.1:8888); overrides config")
@click.option("--project-name", default=None, help="Prefix for all cloud resource names (e.g. experiment name)")
@click.option("--output-file", type=click.Path(path_type=Path), default=None,
              help="Write JSON result {mgmt_ip} to this file after provisioning")
@click.pass_context
def provision(ctx: click.Context, spec: Path, c2c_url: str | None, project_name: str | None, output_file: Path | None) -> None:
    """Provision cloud networks and VMs for a topology (no Ansible).

    SPEC is the path to an environment JSON (e.g. environments/dumbbell.json).
    """
    import json
    from urllib.parse import urlparse
    from config.config import C2CConfig

    config = _load_config(ctx.obj["config_path"], ctx.obj["ansible_verbosity"])
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

    _require_backend_config(config)

    if c2c_url:
        parsed = urlparse(c2c_url)
        config.c2c = C2CConfig(ip=parsed.hostname, port=parsed.port or 8888)

    playbook_registry = PlaybookRegistryService(config)
    backend = build_backend(config, online, project_name=project_name)
    orchestrator = DeploymentOrchestrator(backend, config, online, playbook_registry, project_name=project_name)

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
@click.option("--attacker-play", default=None, help="Runtime play to run on the kali attacker host instead of the registry default")
@click.option("--attacker-only", is_flag=True, help="Run ONLY the kali attacker host's play (skip other hosts + topology plays)")
@click.pass_context
def configure(ctx: click.Context, spec: Path, mgmt_ip: str | None, c2c_url: str | None, project_name: str | None, attacker_play: str | None, attacker_only: bool) -> None:
    """Run Ansible playbooks against a provisioned topology.

    SPEC is the same environment JSON used to provision.
    """
    from urllib.parse import urlparse
    from config.config import C2CConfig

    config = _load_config(ctx.obj["config_path"], ctx.obj["ansible_verbosity"])
    online = OnlineRegistryService(config)
    parser = JsonSpecParser()

    click.echo(f"Parsing spec: {spec}")
    topology = parser.parse(spec)

    _require_backend_config(config)

    if c2c_url:
        parsed = urlparse(c2c_url)
        config.c2c = C2CConfig(ip=parsed.hostname, port=parsed.port or 8888)
    if attacker_play:
        config.attacker_play = attacker_play
    config.attacker_only = attacker_only

    playbook_registry = PlaybookRegistryService(config)
    backend = build_backend(config, online, project_name=project_name)
    orchestrator = DeploymentOrchestrator(backend, config, online, playbook_registry, project_name=project_name)

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
@click.option("--project-name", default=None, help="Prefix for all cloud resource names (e.g. experiment name)")
@click.pass_context
def deploy(ctx: click.Context, spec: Path, validate_only: bool, c2c_url: str | None, project_name: str | None) -> None:
    """Deploy a network topology from a JSON spec file.

    SPEC is the path to an environment JSON (e.g. environments/dumbbell.json).
    """
    from urllib.parse import urlparse
    from config.config import C2CConfig

    config = _load_config(ctx.obj["config_path"], ctx.obj["ansible_verbosity"])
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

    _require_backend_config(config)

    if c2c_url:
        parsed = urlparse(c2c_url)
        config.c2c = C2CConfig(ip=parsed.hostname, port=parsed.port or 8888)

    playbook_registry = PlaybookRegistryService(config)
    backend = build_backend(config, online, project_name=project_name)
    orchestrator = DeploymentOrchestrator(backend, config, online, playbook_registry, project_name=project_name)

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
    config = _load_config(ctx.obj["config_path"], ctx.obj["ansible_verbosity"])
    parser = JsonSpecParser()

    click.echo(f"Parsing spec: {spec}")
    topology = parser.parse(spec)

    if not yes:
        click.confirm(
            f"This will delete all resources for topology '{topology.name}'. Continue?",
            abort=True,
        )

    _require_backend_config(config)

    online = OnlineRegistryService(config)
    playbook_registry = PlaybookRegistryService(config)
    backend = build_backend(config, online, project_name=project_name)
    orchestrator = DeploymentOrchestrator(backend, config, online, playbook_registry, project_name=project_name)

    click.echo(f"Tearing down topology '{topology.name}'...")
    orchestrator.teardown(topology)
    click.echo("Teardown complete.")


# ---------------------------------------------------------------------------
# request-ingress  (defender-requested box ingress)
# ---------------------------------------------------------------------------

def _defender_box_ip(topology) -> str | None:
    for s in topology.get_all_subnets():
        if s.name == "defender_subnet":
            for h in s.hosts:
                if h.ip_address:
                    return str(h.ip_address)
    return None


def _mgmt_ssh(mgmt_ip: str, ssh_key: str, remote: str):
    import os, subprocess
    return subprocess.run(
        ["ssh", "-i", os.path.expanduser(ssh_key), "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "ConnectTimeout=15", f"root@{mgmt_ip}", remote],
        capture_output=True, text=True, timeout=90)


def _mgmt_write(mgmt_ip: str, ssh_key: str, path: str, content: str, mode: str = "0644"):
    import base64
    b64 = base64.b64encode(content.encode()).decode()
    return _mgmt_ssh(mgmt_ip, ssh_key,
                     f"mkdir -p $(dirname {path}) && echo {b64} | base64 -d > {path} && chmod {mode} {path}")


@cli.command(name="request-ingress")
@click.argument("spec", type=click.Path(exists=True, path_type=Path))
@click.option("--project-name", default=None, help="Prefix used when deploying")
@click.option("--mgmt-ip", required=True, help="Management host floating IP (from provisioning)")
@click.option("--telemetry", "telemetry_ports", multiple=True, type=int,
              help="Box port to route relay telemetry to, e.g. 9200 (repeatable)")
@click.option("--forward", "forward_ports", multiple=True, type=int,
              help="Box port to raw-forward victim->mgmt:PORT->box:PORT, e.g. 8000 (repeatable)")
@click.pass_context
def request_ingress(ctx: click.Context, spec: Path, project_name: str | None, mgmt_ip: str,
                    telemetry_ports: tuple, forward_ports: tuple) -> None:
    """Provision DEFENDER-REQUESTED box ingress — exactly the ports the defender asks for, nothing more.

    --telemetry PORT: point the mgmt relay's downstream at the defender box ES (box:PORT). Sensors
       already ship to the relay; this routes them onward to the box. No new firewall port (the relay
       port is already open to victims).
    --forward PORT: raw TCP passthrough victim->mgmt:PORT->box:PORT (server-mediated EDRs like
       Velociraptor). Opens tcp/PORT on the mgmt host from the victim subnets + starts the forwarder.

    A no-defender run never calls this, so the box stays fully isolated (zero open ports).
    """
    config = _load_config(ctx.obj["config_path"], ctx.obj["ansible_verbosity"])
    _require_backend_config(config)
    topology = JsonSpecParser().parse(spec)
    box_ip = _defender_box_ip(topology)
    if not box_ip:
        raise click.ClickException("Topology has no defender_subnet/box; nothing to route ingress to.")
    ssh_key = config.ssh_key_path

    if telemetry_ports:
        import json
        dests = [f"http://{box_ip}:{p}/" for p in telemetry_ports]
        r = _mgmt_write(mgmt_ip, ssh_key, "/etc/telemetry_relay/dests.json",
                        json.dumps({"dests": dests}))
        click.echo(f"telemetry -> relay routes to {dests}: {'ok' if r.returncode == 0 else 'FAILED'}")

    if forward_ports:
        victim_cidrs = sorted({str(s.cidr) for s in topology.get_all_subnets()
                               if not s.external and s.name not in ("attacker_subnet", "defender_subnet")})
        online = OnlineRegistryService(config)
        backend = build_backend(config, online, project_name=project_name)
        aux = (Path(config.playbooks.playbooks_dir) / "aux_files" / "tcp_forward.py").resolve()
        for p in forward_ports:
            backend.add_management_ingress(p, victim_cidrs)
            _mgmt_write(mgmt_ip, ssh_key, "/usr/local/bin/tcp_forward.py", aux.read_text(), mode="0755")
            unit = (f"[Unit]\nDescription=arena TCP forward :{p} -> box\n"
                    "After=network-online.target\nWants=network-online.target\n\n"
                    f"[Service]\nExecStart=/usr/bin/python3 /usr/local/bin/tcp_forward.py {p} {box_ip} {p}\n"
                    "Restart=always\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n")
            _mgmt_write(mgmt_ip, ssh_key, f"/etc/systemd/system/tcp_forward_{p}.service", unit)
            r = _mgmt_ssh(mgmt_ip, ssh_key,
                          f"systemctl daemon-reload && systemctl enable --now tcp_forward_{p}")
            click.echo(f"forward victim->mgmt:{p}->box:{p}: {'ok' if r.returncode == 0 else 'FAILED'}")
    click.echo("request-ingress done.")


# ---------------------------------------------------------------------------
# collect
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("spec", type=click.Path(exists=True, path_type=Path))
@click.option("--mgmt-ip", default=None, required=True, help="Management host floating IP (from provisioning)")
@click.option("--project-name", default=None, help="Prefix used during provisioning")
@click.option("--dest", type=click.Path(path_type=Path), required=True,
              help="Directory to fetch host logs into (files land at <dest>/<host>/<path>)")
@click.pass_context
def collect(ctx: click.Context, spec: Path, mgmt_ip: str, project_name: str | None, dest: Path) -> None:
    """Fetch each host's ground-truth logs before teardown.

    SPEC is the same environment JSON used to provision. Pulls auth.log/syslog, auditd logs,
    cmdlog, the /etc/passwd + /etc/group id maps, and the auditctl -l / -s dumps (loaded rules +
    lost-event count) from every host to <dest>/<host>/ over the bastion ProxyJump.
    """
    config = _load_config(ctx.obj["config_path"], ctx.obj["ansible_verbosity"])
    online = OnlineRegistryService(config)
    parser = JsonSpecParser()

    click.echo(f"Parsing spec: {spec}")
    topology = parser.parse(spec)

    _require_backend_config(config)

    playbook_registry = PlaybookRegistryService(config)
    backend = build_backend(config, online, project_name=project_name)
    orchestrator = DeploymentOrchestrator(backend, config, online, playbook_registry, project_name=project_name)

    click.echo(f"Collecting host logs for '{topology.name}' -> {dest}...")
    orchestrator.collect(topology, mgmt_ip, str(dest))
    click.echo("Collection complete.")


# ---------------------------------------------------------------------------
# rotate-logs
# ---------------------------------------------------------------------------

@cli.command(name="rotate-logs")
@click.argument("spec", type=click.Path(exists=True, path_type=Path))
@click.option("--mgmt-ip", default=None, required=True, help="Management host floating IP (from provisioning)")
@click.option("--project-name", default=None, help="Prefix used during provisioning")
@click.pass_context
def rotate_logs(ctx: click.Context, spec: Path, mgmt_ip: str, project_name: str | None) -> None:
    """Reset each host's ground-truth logs at the deploy->attack boundary.

    SPEC is the same environment JSON used to provision. Truncates/rotates auth.log/syslog/auditd/
    cmdlog on every host over the bastion ProxyJump so post-experiment collection yields only
    attack-phase activity. The harness blocks the attacker on this completing.
    """
    config = _load_config(ctx.obj["config_path"], ctx.obj["ansible_verbosity"])
    online = OnlineRegistryService(config)
    parser = JsonSpecParser()

    click.echo(f"Parsing spec: {spec}")
    topology = parser.parse(spec)

    _require_backend_config(config)

    playbook_registry = PlaybookRegistryService(config)
    backend = build_backend(config, online, project_name=project_name)
    orchestrator = DeploymentOrchestrator(backend, config, online, playbook_registry, project_name=project_name)

    click.echo(f"Rotating host logs for '{topology.name}'...")
    orchestrator.rotate_logs(topology, mgmt_ip)
    click.echo("Rotation complete.")


if __name__ == "__main__":
    cli()
