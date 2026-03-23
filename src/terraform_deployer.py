import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import openstack.compute.v2.server
import openstack.image.v2.image
from src.terraform_helpers import deploy_network
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
from ansible.caldera import InstallAttacker
from ansible.defender import InstallSysFlow
from ansible.defender.falco.install_falco import InstallFalco

from src.utility.logging import get_logger

logger = get_logger()


def find_manage_server(
    conn,
) -> tuple[openstack.compute.v2.server.Server | None, str | None]:
    """Finds any server with a floating IP and returns the first one found."""
    for server in conn.compute.servers():
        for network, network_attrs in server.addresses.items():
            for addr_info in network_attrs:
                # Check if this address is a floating IP
                if addr_info.get("OS-EXT-IPS:type") == "floating":
                    ip = addr_info["addr"]
                    return server, ip
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

    # Protofunction, this is where you define everything needed to setup the instance
    def compile_setup(self):
        return

    def runtime_setup(self):
        install_trials = 5
        errors = 0

        for _ in range(install_trials):
            try:
                attacker_host = self.attacker_host
                self.ansible_runner.run_playbook(
                    InstallAttacker(attacker_host.ip, "root", self.caldera_ip)
                )
                break
            except Exception:
                errors += 1
                time.sleep(30)

        if errors == install_trials:
            raise Exception(
                f"Failed to install attacker host after {install_trials} trials"
            )

    def parse_network(self):
        return

    def teardown(self):
        print("Tearing down...")

        conn = self.openstack_conn

        teardown_helper.delete_instances(conn)
        while conn.list_servers():
            time.sleep(0.5)

        teardown_helper.delete_floating_ips(conn)
        while conn.list_floating_ips():
            time.sleep(0.5)

        teardown_helper.delete_routers(conn)
        while conn.list_routers():
            time.sleep(0.5)

        teardown_helper.delete_subnets(conn)
        teardown_helper.delete_networks(conn)
        teardown_helper.delete_security_groups(conn)

    def compile(self, setup_network: bool = True, setup_hosts: bool = True):
        if setup_network:
            # Redeploy entire network
            self.deploy_topology()
            time.sleep(5)

        self.find_management_server()
        self.parse_network()

        if setup_hosts:
            # Setup instances
            self.setup_base_packages()
            self.compile_setup()

        # Save instance
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
        self.find_management_server()
        self.parse_network()
        # Load snapshots
        self.load_all_snapshots()
        time.sleep(10)
        while self.get_error_hosts():
            self.rebuild_error_hosts()

    def deploy_topology(self):
        self.teardown()
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

        # # Group servers by flavor size, largest first, to avoid starvation.
        # # Flavor names come from config so we can map actual name → logical size.
        # size_order = ["huge", "large", "medium", "small", "tiny"]
        # flavors = self.config.terraform_config.flavors
        # flavor_to_size = {getattr(flavors, size): size for size in size_order}
        #
        # buckets: dict[str, list] = {size: [] for size in size_order}
        # unrecognized: list = []
        # for server in servers:
        #     flavor_name = (server.flavor or {}).get("original_name", "")
        #     size = flavor_to_size.get(flavor_name)
        #     if size:
        #         buckets[size].append(server)
        #     else:
        #         unrecognized.append(server)
        #
        # for size in size_order:
        #     group = buckets[size]
        #     if not group:
        #         continue
        #     print(f"[SNAPSHOT] Starting {size} tier ({len(group)} server(s))...")
        #     self._snapshot_group(group, batch_size)
        #     print(f"[SNAPSHOT] {size} tier complete.")
        #
        # if unrecognized:
        #     print(f"[SNAPSHOT] Snapshotting {len(unrecognized)} server(s) with unrecognized flavor...")
        #     self._snapshot_group(unrecognized, batch_size)

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
            self.load_snapshot(host, wait=True)

        return
