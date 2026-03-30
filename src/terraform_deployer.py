import time
from src.image_baker import VmBakeSpec, ImageBaker

import openstack.compute.v2.server
from src.terraform_helpers import deploy_network
from src.topology_manifests import TOPOLOGY_VM_COUNTS
from src.utility.openstack_helper_functions import teardown_helper
import openstack
from openstack.connection import Connection
from ansible.ansible_runner import AnsibleRunner
from config.config import Config
from src.legacy_models.network import Host, Network
from ansible.deployment_instance import (
    InstallKaliPackages,
    CheckIfHostUp,
    InstallBasePackages,
    CreateSSHKey,
)
from ansible.defender import InstallSysFlow
from ansible.defender.falco.install_falco import InstallFalco
from src.image_baker import ImageBaker, VmBakeSpec

from src.webhook_notifier import WebhookNotifier
from src.utility.logging import get_logger

logger = get_logger()


def find_manage_server(
    conn,
) -> tuple[openstack.compute.v2.server.Server | None, str | None]:
    """Finds any server with a floating IP and returns the first one found.

    Nova ignores project_id filters for admin tokens, so filter client-side
    by the project name prefix embedded in every server's name (e.g. "perry_slot0-").
    """
    project_name = conn.auth.get("project_name", "") if conn.auth else ""
    project_prefix = f"{project_name}-" if project_name else ""

    for server in conn.compute.servers():
        if project_prefix and not server.name.startswith(project_prefix):
            continue
        for network, network_attrs in server.addresses.items():
            for addr_info in network_attrs:
                if addr_info.get("OS-EXT-IPS:type") == "floating":
                    return server, addr_info["addr"]
    return None, None


class TerraformDeployer:
    def __init__(
        self,
        ansible_runner: AnsibleRunner,
        openstack_conn: Connection,
        external_ip: str,
        config: Config,
    ):
        self.ansible_runner: AnsibleRunner = ansible_runner
        self.openstack_conn: Connection = openstack_conn
        self.ssh_key_path = "./environment/ssh_keys/"
        self.caldera_ip = external_ip
        self.config = config
        self.all_instances = None
        self.topology: str
        self.attacker_host: Host
        self.network: Network

        self.hosts = {}

        self.flags = {}
        self.root_flags = {}

        self._notifier: WebhookNotifier | None = (
            WebhookNotifier(config.webhook_config.url, config.webhook_config.type)
            if config.webhook_config else None
        )
        self._label = type(self).__name__

    # ------------------------------------------------------------------
    # Image-bake API — override in subclasses to enable the bake flow.
    # ------------------------------------------------------------------

    def vm_bake_specs(self) -> list[VmBakeSpec]:
        """Return one VmBakeSpec per logical VM type for this environment.

        Each spec declares:
          • which base Glance image to start from
          • which Ansible playbooks to apply during baking (in order)
          • the name under which the finished image is stored in Glance
          • optional extra Ansible vars (e.g. Elasticsearch credentials)
          • optional per-host setup playbook factories for setup time

        Override this in environment subclasses.
        """
        return []

    # Protofunction, this is where you define everything needed to setup the instance
    def compile_setup(self):
        return

    def runtime_setup(self):
        pass

    def vm_bake_specs(self) -> list[VmBakeSpec]:
        return []

    def parse_network(self):
        return

    def _teardown_impl(self):
        print("Tearing down...")

        conn = self.openstack_conn

        project_prefix = self.config.openstack_config.project_name + "-"

        print("Collecting floating IPs...")
        fip_ids = teardown_helper.collect_floating_ips(conn, name_prefix=project_prefix)

        print("Deleting instances...")
        teardown_helper.delete_instances(conn, name_prefix=project_prefix)
        while True:
            servers = [s for s in conn.list_servers() if s.name.startswith(project_prefix)]
            if not servers:
                break
            print(f"  Waiting for {len(servers)} server(s) to delete: {[s.name for s in servers]}")
            time.sleep(0.5)
        print("Instances deleted.")
        # Give Neutron a moment to release ports after Nova finishes deletions.
        time.sleep(5)

        print("Deleting floating IPs...")
        teardown_helper.delete_floating_ips(conn, fip_ids=fip_ids)
        while True:
            remaining = [f for f in conn.list_floating_ips(filters={"project_id": conn.current_project_id}) if f.id in fip_ids]
            if not remaining:
                break
            print(f"  Waiting for {len(remaining)} floating IP(s) to delete.")
            time.sleep(0.5)
        print("Floating IPs deleted.")

        print("Deleting ports...")
        teardown_helper.delete_ports(conn, name_prefix=project_prefix)

        print("Deleting routers...")
        teardown_helper.delete_routers(conn, name_prefix=project_prefix)
        while True:
            routers = [r for r in conn.list_routers(filters={"project_id": conn.current_project_id}) if r.name.startswith(project_prefix)]
            if not routers:
                break
            print(f"  Waiting for {len(routers)} router(s) to delete: {[r.name for r in routers]}")
            time.sleep(0.5)
        print("Routers deleted.")
        print("Deleting subnets...")
        teardown_helper.delete_subnets(conn, name_prefix=project_prefix)
        print("Deleting networks...")
        teardown_helper.delete_networks(conn, name_prefix=project_prefix)
        print("Deleting security groups...")
        teardown_helper.delete_security_groups(conn, name_prefix=project_prefix)
        print("Teardown complete.")

    def _wait_for_servers_active(self, timeout: int = 1200) -> None:
        """Poll until all expected VMs are ACTIVE with network addresses, or raise on timeout."""
        project_prefix = self.config.openstack_config.project_name + "-"
        expected = TOPOLOGY_VM_COUNTS.get(self.topology)
        if expected is not None:
            print(f"[deploy] Waiting for {expected} VMs to become ACTIVE...")
        else:
            print("[deploy] Waiting for all VMs to become ACTIVE (count unknown)...")

        deadline = time.time() + timeout
        rebooted: set[str] = set()  # server IDs that have already had one recovery attempt
        while True:
            servers = [s for s in self.openstack_conn.list_servers() if s.name.startswith(project_prefix)]
            errored = [s for s in servers if s.status == "ERROR"]
            for s in errored:
                if s.id in rebooted:
                    raise RuntimeError(
                        f"Server {s.name} returned to ERROR after reboot; giving up."
                    )
                print(f"[deploy] Server {s.name} is in ERROR; resetting state and hard rebooting...")
                try:
                    self.openstack_conn.compute.reset_server_state(s.id, state="active")
                    self.openstack_conn.compute.reboot_server(s.id, reboot_type="HARD")
                except Exception as e:
                    raise RuntimeError(f"Could not recover errored server {s.name}: {e}")
                rebooted.add(s.id)
            ready = [s for s in servers if s.status == "ACTIVE" and s.addresses]
            not_ready = [s.name for s in servers if s not in ready]
            count_ok = expected is None or len(ready) >= expected
            if count_ok and not not_ready:
                print(f"[deploy] All {len(ready)} VMs ACTIVE with addresses.")
                return
            if time.time() > deadline:
                raise TimeoutError(
                    f"Timed out after {timeout}s waiting for VMs. "
                    f"Ready: {len(ready)}/{expected or '?'}. "
                    f"Not ready: {not_ready}"
                )
            status = f"{len(ready)}/{expected or '?'} ready"
            if not_ready:
                status += f", waiting on: {not_ready}"
            print(f"[deploy] {status}...")
            time.sleep(10)

    def teardown(self):
        if self._notifier:
            self._notifier.notify_start("teardown", self._label)
        _start = time.time()
        try:
            self._teardown_impl()
            if self._notifier:
                self._notifier.notify_success("teardown", self._label, time.time() - _start)
        except Exception as exc:
            if self._notifier:
                self._notifier.notify_error("teardown", self._label, time.time() - _start, exc)
            raise

    def compile(self, setup_network: bool = True, setup_hosts: bool = True, keep_cache: bool = False):
        if self._notifier:
            self._notifier.notify("compile", self._label,
                                  lambda: self._compile_impl(setup_network, setup_hosts, keep_cache))
        else:
            self._compile_impl(setup_network, setup_hosts, keep_cache)

    def _compile_impl(self, setup_network: bool = True, setup_hosts: bool = True, keep_cache: bool = False):
        baker = ImageBaker(self.openstack_conn)
        baker.bake_all(self.vm_bake_specs(), keep_cache=keep_cache)

    def setup(self):
        if self._notifier:
            self._notifier.notify("setup", self._label, self._setup_impl)
        else:
            self._setup_impl()

    def _setup_impl(self):
        def _notify(operation, fn):
            if self._notifier:
                self._notifier.notify(operation, self._label, fn)
            else:
                fn()

        _notify("deploy", self.deploy_topology)
        self._wait_for_servers_active()
        self.find_management_server()
        self.parse_network()
        _notify("ansible", lambda: (self._run_host_setup_playbooks(), self.compile_setup()))

    def _apply_baked_images_to_config(self, specs: list[VmBakeSpec]) -> None:
        """Write baked image names into the in-memory Terraform config so that
        deploy_topology() passes them as Terraform variables."""
        images = self.config.terraform_config.images
        for spec in specs:
            field_name = f"{spec.type_name}_baked"
            if hasattr(images, field_name):
                setattr(images, field_name, spec.baked_image_name)

    def _run_host_setup_playbooks(self) -> None:
        """For each live host, run the setup playbook factories registered in
        the matching VmBakeSpec (matched by host-name prefix == type_name).

        Hosts are processed in parallel, but each host's playbooks run
        sequentially to preserve intra-host dependencies (e.g. CreateUser
        must complete before AddData on the same host)."""
        specs_by_type = {spec.type_name: spec for spec in self.vm_bake_specs()}
        per_host_playbooks: list[list] = []
        for host in self.network.get_all_hosts():
            # Match the host to a spec by the longest matching type_name prefix.
            matched_spec = None
            for type_name, spec in specs_by_type.items():
                # Strip project-name prefix (e.g. "perry-webserver_0" → "webserver")
                bare_name = host.name.split("-", 1)[-1] if "-" in host.name else host.name
                if bare_name.startswith(type_name) and (
                    matched_spec is None
                    or len(type_name) > len(matched_spec.type_name)
                ):
                    matched_spec = spec
            if matched_spec is None:
                continue
            host_playbooks = [
                p for factory in matched_spec.setup_playbook_factories
                if (p := factory(host)) is not None
            ]
            if host_playbooks:
                per_host_playbooks.append(host_playbooks)

        if not per_host_playbooks:
            return

        for playbooks in per_host_playbooks:
            self.ansible_runner.run_playbooks_serial(playbooks)

    def deploy_topology(self) -> None:
        bake_specs = self.vm_bake_specs()
        if bake_specs:
            self._apply_baked_images_to_config(bake_specs)
            unique_baked = {spec.baked_image_name for spec in bake_specs if spec.baked_image_name}
            missing = [name for name in unique_baked if not self.openstack_conn.get_image(name)]
            if missing:
                raise RuntimeError(
                    f"Baked images not found in Glance — run compile first: {missing}"
                )
        self._teardown_impl()
        deploy_network(self.topology, self.config)

    def find_management_server(self):
        manage_network, manage_ip = find_manage_server(self.openstack_conn)
        logger.debug(f"Found management server: {manage_ip}")
        self.ansible_runner.update_management_ip(manage_ip)







