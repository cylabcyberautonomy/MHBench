import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.image_baker import VmBakeSpec, ImageBaker

import openstack.compute.v2.server
import openstack.image.v2.image
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

        When this returns a non-empty list, compile() uses ImageBaker to
        bake each type (skipping any that already exist in Glance) and then
        deploys Terraform using the baked images.  When it returns an empty
        list the old in-place Ansible flow is used instead (backward compat).

        Override this in environment subclasses that want the bake flow.
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

    def _rebuild_vms(self) -> None:
        """Re-flash each VM's disk from its baked image without destroying the VM.

        This is faster than deploy_topology() (no network teardown/create) and
        leaves IPs intact so parse_network() results remain valid across trials.
        Called at the start of every trial in the bake flow instead of deploy_topology().
        """
        bake_specs = self.vm_bake_specs()
        specs_by_type = {spec.type_name: spec for spec in bake_specs}
        project_prefix = self.config.openstack_config.project_name + "-"

        servers = [s for s in self.openstack_conn.list_servers() if s.name.startswith(project_prefix)]
        if not servers:
            raise RuntimeError(
                f"No VMs found with prefix '{project_prefix}'. "
                "Run deploy_topology() (via compile) before setup()."
            )

        # Resolve image IDs and build the rebuild list up front.
        image_cache: dict[str, str] = {}
        rebuild_list: list[tuple] = []  # (server, image_id, image_name)
        for server in servers:
            bare_name = server.name[len(project_prefix):]
            matched_spec = None
            for type_name, spec in specs_by_type.items():
                if bare_name.startswith(type_name) and (
                    matched_spec is None or len(type_name) > len(matched_spec.type_name)
                ):
                    matched_spec = spec

            if matched_spec is None:
                print(f"[rebuild] No bake spec for '{server.name}', skipping")
                continue

            if matched_spec.baked_image_name not in image_cache:
                image = self.openstack_conn.get_image(matched_spec.baked_image_name)
                if image is None:
                    raise RuntimeError(
                        f"Baked image '{matched_spec.baked_image_name}' not found in Glance. "
                        "Run compile first."
                    )
                image_cache[matched_spec.baked_image_name] = image.id

            rebuild_list.append((server, image_cache[matched_spec.baked_image_name], matched_spec.baked_image_name))

        # Issue rebuilds in batches and wait for each batch to finish before
        # starting the next. This prevents saturating hypervisor disk I/O from
        # too many simultaneous Glance image downloads on the same node.
        batch_size = 5
        # Collect VMs that enter ERROR during any batch; retry them after all
        # batches complete once the rest of the cluster has settled.
        errored_entries: list[tuple] = []  # (server, image_id, image_name)

        for i in range(0, len(rebuild_list), batch_size):
            batch = rebuild_list[i:i + batch_size]
            batch_ids = {server.id for server, _, _ in batch}
            id_to_entry = {server.id: (server, image_id, image_name) for server, image_id, image_name in batch}

            for server, image_id, image_name in batch:
                print(f"[rebuild] Rebuilding '{server.name}' from '{image_name}'")
                self.openstack_conn.compute.rebuild_server(server.id, image_id)

            # Wait for OpenStack to transition batch VMs out of ACTIVE before polling.
            time.sleep(15)

            # Wait for this batch to reach a terminal state (ACTIVE or ERROR).
            # Collect errored VMs rather than raising immediately.
            deadline = time.time() + 1200
            settled_ids: set[str] = set()
            while True:
                current = {s.id: s for s in self.openstack_conn.list_servers() if s.id in batch_ids}
                for sid, s in current.items():
                    if sid in settled_ids:
                        continue
                    if s.status == "ERROR":
                        print(f"[rebuild] '{s.name}' entered ERROR; will retry after other VMs settle.")
                        errored_entries.append(id_to_entry[sid])
                        settled_ids.add(sid)
                    elif s.status == "ACTIVE" and s.addresses:
                        settled_ids.add(sid)
                if settled_ids >= batch_ids:
                    active_count = len(batch_ids) - sum(
                        1 for sid in settled_ids if current.get(sid) and current[sid].status == "ERROR"
                    )
                    print(f"[rebuild] Batch {i // batch_size + 1} settled ({active_count}/{len(batch)} ACTIVE).")
                    break
                if time.time() > deadline:
                    raise TimeoutError(f"Timed out waiting for rebuild batch {i // batch_size + 1}")
                time.sleep(10)

        # Retry errored VMs (up to 3 attempts) after all batches have settled.
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            if not errored_entries:
                break

            # Wait for every non-errored VM to be ACTIVE so hypervisor load
            # has dropped before issuing new rebuild requests.
            all_ids = {server.id for server, _, _ in rebuild_list}
            errored_ids = {server.id for server, _, _ in errored_entries}
            non_errored_ids = all_ids - errored_ids
            if non_errored_ids:
                print(
                    f"[rebuild] Waiting for {len(non_errored_ids)} non-errored VMs to be ACTIVE "
                    f"before retry attempt {attempt}/{max_retries}..."
                )
                deadline = time.time() + 1200
                while True:
                    current = {s.id: s for s in self.openstack_conn.list_servers() if s.id in non_errored_ids}
                    ready = {sid for sid, s in current.items() if s.status == "ACTIVE" and s.addresses}
                    if ready >= non_errored_ids:
                        break
                    if time.time() > deadline:
                        raise TimeoutError(
                            f"Timed out waiting for non-errored VMs to become ACTIVE before retry attempt {attempt}"
                        )
                    time.sleep(10)

            print(f"[rebuild] Retry attempt {attempt}/{max_retries}: rebuilding {len(errored_entries)} VM(s)...")
            retry_ids = {server.id for server, _, _ in errored_entries}
            id_to_entry = {server.id: (server, image_id, image_name) for server, image_id, image_name in errored_entries}
            for server, image_id, image_name in errored_entries:
                print(f"[rebuild] Retry rebuild '{server.name}' from '{image_name}'")
                self.openstack_conn.compute.rebuild_server(server.id, image_id)

            time.sleep(15)
            errored_entries = []
            deadline = time.time() + 1200
            settled_ids = set()
            while True:
                current = {s.id: s for s in self.openstack_conn.list_servers() if s.id in retry_ids}
                for sid, s in current.items():
                    if sid in settled_ids:
                        continue
                    if s.status == "ERROR":
                        print(f"[rebuild] '{s.name}' still ERROR on attempt {attempt}; will retry again.")
                        errored_entries.append(id_to_entry[sid])
                        settled_ids.add(sid)
                    elif s.status == "ACTIVE" and s.addresses:
                        settled_ids.add(sid)
                if settled_ids >= retry_ids:
                    active_count = len(retry_ids) - len(errored_entries)
                    print(f"[rebuild] Retry attempt {attempt} settled ({active_count}/{len(retry_ids)} ACTIVE).")
                    break
                if time.time() > deadline:
                    raise TimeoutError(f"Timed out waiting for errored VMs on retry attempt {attempt}")
                time.sleep(10)

        if errored_entries:
            names = [server.name for server, _, _ in errored_entries]
            raise RuntimeError(f"VMs still in ERROR after {max_retries} retry attempts: {names}")

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
            self._notifier.notify_start("compile", self._label)
        _start = time.time()
        try:
            self._compile_impl(setup_network, setup_hosts, keep_cache)
            if self._notifier:
                self._notifier.notify_success("compile", self._label, time.time() - _start)
        except Exception as exc:
            if self._notifier:
                self._notifier.notify_error("compile", self._label, time.time() - _start, exc)
            raise

    def _compile_impl(self, setup_network: bool = True, setup_hosts: bool = True, keep_cache: bool = False):
        bake_specs = self.vm_bake_specs()

        if bake_specs:
            # ── New bake-image flow ──────────────────────────────────────
            # 1. Bake a qcow2 image for every VM type that has not been baked
            #    yet, then upload the result to OpenStack Glance so that
            #    Terraform can reference it by name.
            baker = ImageBaker(self.openstack_conn, availability_zone=self.config.availability_zone)
            baker.bake_all(bake_specs, keep_cache=keep_cache)
            return

        # ── Legacy in-place Ansible flow (no bake specs defined) ─────────
        if setup_network:
            self.deploy_topology()
            self._wait_for_servers_active()

        self.find_management_server()
        self.parse_network()

        if setup_hosts:
            self.setup_base_packages()
            self.compile_setup()

        self.clean_snapshots()
        self.save_all_snapshots()

    def setup_base_packages(self):
        self.ansible_runner.run_playbook(CheckIfHostUp(self.attacker_host.ip))
        time.sleep(3)

        self.ansible_runner.run_playbook(
            InstallBasePackages(self.network.get_all_host_ips())
        )
        self.ansible_runner.run_playbook(InstallKaliPackages(self.attacker_host.ip))
        self.ansible_runner.run_playbook(CreateSSHKey(self.attacker_host.ip, "root"))

        # Install sysflow on all hosts
        self.ansible_runner.run_playbook(
            InstallSysFlow(self.network.get_all_host_ips(), self.config)
        )
        self.ansible_runner.run_playbook(
            InstallFalco(self.network.get_all_host_ips(), self.config)
        )

    def setup(self):
        if self._notifier:
            self._notifier.notify("setup", self._label, self._setup_impl)
        else:
            self._setup_impl()

    def _setup_impl(self):
        bake_specs = self.vm_bake_specs()

        def _notify(operation, fn):
            if self._notifier:
                self._notifier.notify(operation, self._label, fn)
            else:
                fn()

        if bake_specs:
            _notify("deploy", self.deploy_topology)
            self._wait_for_servers_active()
            self.find_management_server()
            self.parse_network()
            _notify("ansible", lambda: (self._run_host_setup_playbooks(), self.compile_setup()))
        else:
            # ── Legacy snapshot flow ──────────────────────────────────────
            self.find_management_server()
            self.parse_network()
            self.load_all_snapshots()
            time.sleep(10)
            while self.get_error_hosts():
                self.rebuild_error_hosts()

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

        errors = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self.ansible_runner.run_playbooks_serial, playbooks): playbooks
                for playbooks in per_host_playbooks
            }
            for future in as_completed(futures):
                exc = future.exception()
                if exc:
                    errors.append(exc)

        if errors:
            raise RuntimeError(f"{len(errors)} host(s) failed setup playbooks: {errors}")

    def deploy_topology(self) -> None:
        bake_specs = self.vm_bake_specs()
        if bake_specs:
            self._apply_baked_images_to_config(bake_specs)
        self._teardown_impl()
        deploy_network(self.topology, self.config)

    def find_management_server(self):
        manage_network, manage_ip = find_manage_server(self.openstack_conn)
        logger.debug(f"Found management server: {manage_ip}")
        self.ansible_runner.update_management_ip(manage_ip)

    def save_snapshot(self, host, poll_interval=120, max_attempts=3):
        snapshot_name = host.name + "_image"

        for attempt in range(1, max_attempts + 1):
            image = self.openstack_conn.get_image(snapshot_name)
            if image:
                logger.debug(f"Image '{snapshot_name}' already exists. Deleting...")
                self.openstack_conn.delete_image(image.id, wait=True)  # type: ignore

            # Wait for any in-progress upload to finish before issuing a new
            # createImage — otherwise Nova returns 409 Conflict.
            while True:
                server = self.openstack_conn.get_server_by_id(host.id)
                if server and getattr(server, "task_state", None) == "image_uploading":
                    time.sleep(30)
                else:
                    break

            print(f"[SNAPSHOT] {snapshot_name}: starting (attempt {attempt}/{max_attempts})...")
            self.openstack_conn.create_image_snapshot(snapshot_name, host.id, wait=False)

            while True:
                time.sleep(poll_interval)
                image = self.openstack_conn.get_image(snapshot_name)
                if image and image.status == "active":
                    print(f"[SNAPSHOT] {snapshot_name}: done.")
                    return image.id
                if not image or image.status not in ("queued", "saving"):
                    status = image.status if image else "missing"
                    print(f"[SNAPSHOT] {snapshot_name}: upload lost on attempt {attempt}/{max_attempts} (status={status}), retrying...")
                    break

        raise RuntimeError(f"[SNAPSHOT] {snapshot_name}: failed after {max_attempts} attempts")

    def load_snapshot(self, host, wait=False):
        snapshot_name = host.name + "_image"
        try:
            image: openstack.image.v2.image.Image = self.openstack_conn.get_image(
                snapshot_name
            )  # type: ignore
        except AttributeError as e:
            print(f"No image for host {snapshot_name}")
            raise e

        if image:
            logger.debug(
                f"Loading snapshot {snapshot_name} for instance {host.name}..."
            )
            self.openstack_conn.rebuild_server(
                host.id, image.id, wait=wait, admin_pass=None
            )
            if wait:
                logger.debug(
                    f"Successfully loaded snapshot {snapshot_name} with id {image.id}"
                )

    def _snapshot_group(self, servers, batch_size):
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            futures = {executor.submit(self.save_snapshot, s): s for s in servers}
            for future in as_completed(futures):
                server = futures[future]
                exc = future.exception()
                if exc:
                    logger.warning(f"[SNAPSHOT] {server.name} thread exited with error: {exc}")
                else:
                    logger.debug(f"Snapshot saved for {server.name}")

    def save_all_snapshots(self, batch_size=5):
        servers = list(self.openstack_conn.list_servers())
        logger.debug(f"Saving snapshots for {len(servers)} servers (batch_size={batch_size})...")
        
        self._snapshot_group(servers, batch_size)

        while True:
            missing = []
            for s in servers:
                image = self.openstack_conn.get_image(s.name + "_image")
                if not image or image.status != "active":
                    missing.append(s)
            if not missing:
                break
            print(f"[SNAPSHOT] {len(missing)} image(s) not active, retrying: {[s.name for s in missing]}")
            self._snapshot_group(missing, batch_size)

    def clean_snapshots(self):
        logger.debug("Cleaning all snapshots...")
        images = self.openstack_conn.list_images()
        for image in images:
            if "_image" in image.name:
                self.openstack_conn.delete_image(image.id, wait=True)

    def load_all_snapshots(self, wait=True):
        logger.debug("Loading all snapshots...")
        hosts: openstack.compute.v2.server.Server = self.openstack_conn.list_servers()  # type: ignore

        # Check if all images exist
        hosts_to_rebuild = []
        for host in hosts:
            image = self.openstack_conn.get_image(host.name + "_image")
            if not image:
                # Skip hosts that don't have snapshots (like dynamically created decoys)
                # These are typically decoys created during previous experiments
                if host.name.startswith("decoy"):
                    logger.warning(
                        f"Skipping decoy host {host.name} - no snapshot image exists, will delete"
                    )
                    # Delete the decoy host since it doesn't have a proper snapshot
                    try:
                        self.openstack_conn.delete_server(host.id, wait=True)
                        logger.info(f"Deleted orphaned decoy host {host.name}")
                    except Exception as e:
                        logger.error(
                            f"Failed to delete orphaned decoy host {host.name}: {e}"
                        )
                    continue
                else:
                    raise Exception(f"Image {host.name + '_image'} does not exist")
            hosts_to_rebuild.append(host)

        rebuild_num = 10
        # Rebuild 10 servers at a time
        for i in range(0, len(hosts_to_rebuild), rebuild_num):
            hosts_to_restore = []
            if i + 5 < len(hosts_to_rebuild):
                hosts_to_restore = hosts_to_rebuild[i : i + rebuild_num]
            else:
                hosts_to_restore = hosts_to_rebuild[i:]

            # Start rebuilding all servers
            for host in hosts_to_restore:
                self.load_snapshot(host, wait=False)

            # Wait for rebuild to start
            time.sleep(5)

            # Wait for 5 servers to be rebuilt
            waiting_for_rebuild = True
            while waiting_for_rebuild:
                waiting_for_rebuild = False
                for host in hosts_to_restore:
                    curr_host = self.openstack_conn.get_server_by_id(host.id)
                    if curr_host and curr_host.status == "REBUILD":
                        waiting_for_rebuild = True

                time.sleep(1)

        for host in hosts:
            if "attacker" in host.name:
                # Weird bug in Kali where after rebuilding sometimes needs to be rebooted
                time.sleep(10)
                self.openstack_conn.compute.reboot_server(host.id, reboot_type="HARD")  # type: ignore
                while True:
                    current = self.openstack_conn.get_server_by_id(host.id)
                    if current and current.status == "ACTIVE":
                        break
                    time.sleep(1)
        return

    def get_error_hosts(self):
        hosts: openstack.compute.v2.server.Server = self.openstack_conn.list_servers()  # type: ignore
        error_hosts = []

        for host in hosts:
            if host.status == "ERROR":
                error_hosts.append(host)

        return error_hosts

    def rebuild_error_hosts(self):
        error_hosts = self.get_error_hosts()
        for host in error_hosts:
            self.openstack_conn.delete_server(host.id, wait=True)
            self.load_snapshot(host.private_v4, wait=True)

        return
