from __future__ import annotations

import logging
import time

from openstack.connection import Connection

from config.config import Config
from src.abstractions.network import Host, NetworkTopology
from src.deployment.online_registry_service import OnlineRegistryService

logger = logging.getLogger(__name__)

_BATCH_SIZE = 10
_DEPLOY_TIMEOUT = 600
_DELETE_TIMEOUT = 300
_POLL_INTERVAL = 5


class HostDeployer:

    def __init__(self, conn: Connection, config: Config, online_registry: OnlineRegistryService, project_name: str | None = None) -> None:
        self._conn = conn
        self._project_id = conn.current_project_id
        self._ssh_key_name = config.openstack.keypair_name
        self._management = config.management
        self._online = online_registry
        self._project_name = project_name

    def _n(self, name: str) -> str:
        return f"{self._project_name}-{name}" if self._project_name else name

    def _log_instance_info(self, name: str, server, flavor, image) -> None:
        img_size = getattr(image, "size", None)
        img_size_str = f"{img_size / 1e9:.2f} GB" if img_size else "unknown"

        networks = []
        for net_name, addrs in (server.addresses or {}).items():
            fixed = [a["addr"] for a in addrs if a.get("OS-EXT-IPS:type") == "fixed"]
            floating = [a["addr"] for a in addrs if a.get("OS-EXT-IPS:type") == "floating"]
            addr_str = ", ".join(fixed)
            if floating:
                addr_str += f"  (floating: {', '.join(floating)})"
            networks.append(f"    {net_name}: {addr_str}")

        sgs = [sg.get("name", "") for sg in (server.security_groups or [])]

        lines = [
            f"Instance ready: {name}",
            f"  Identity:",
            f"    UUID:              {server.id}",
            f"    Name:              {server.name}",
            f"    Created:           {getattr(server, 'created_at', None)}",
            f"  Placement:",
            f"    Hypervisor:        {getattr(server, 'hypervisor_hostname', None)}",
            f"    Host ID:           {getattr(server, 'host_id', None)}",
            f"    Availability zone: {getattr(server, 'availability_zone', None)}",
            f"  Flavor:              {flavor.name}",
            f"    vCPUs:             {flavor.vcpus}",
            f"    RAM:               {flavor.ram} MB",
            f"    Disk:              {flavor.disk} GB",
            f"    Ephemeral:         {getattr(flavor, 'ephemeral', 0)} GB",
            f"  Image:               {image.name}",
            f"    ID:                {image.id}",
            f"    Size:              {img_size_str}",
            f"    Min disk:          {getattr(image, 'min_disk', None)} GB",
            f"    Min RAM:           {getattr(image, 'min_ram', None)} MB",
            f"  Networks:",
            *networks,
            f"  Security groups:     {', '.join(sgs)}",
            f"  Power state:         {getattr(server, 'power_state', None)}",
        ]
        logger.info("\n".join(lines))

    def deploy(self, topology: NetworkTopology) -> str | None:
        mgmt_floating_ip: str | None = None

        if self._management:
            mgmt = self._management
            base_image_name = self._online.get_base_image(mgmt.vm_type)
            image = self._conn.image.find_image(base_image_name)
            if not image:
                raise RuntimeError(f"Image '{base_image_name}' not found in Glance.")
            flavor = self._conn.compute.find_flavor(mgmt.flavor)
            if not flavor:
                raise RuntimeError(f"Flavor '{mgmt.flavor}' not found in OpenStack.")
            os_mgmt_net = self._conn.network.find_network(self._n("management_network"), project_id=self._project_id)
            if not os_mgmt_net:
                raise RuntimeError(f"OpenStack network '{self._n('management_network')}' not found.")

            logger.info("Submitting: %s  image=%s  flavor=%s", self._n("management_host"), image.name, flavor.name)
            time.sleep(1)
            server = self._conn.compute.create_server(
                name=self._n("management_host"),
                imageRef=image.id,
                flavorRef=flavor.id,
                networks=[{"uuid": os_mgmt_net.id, "fixed_ip": mgmt.host_ip}],
                security_groups=[{"name": self._n("management_sg")}],
                key_name=self._ssh_key_name,
            )
            time.sleep(1)
            deadline = time.monotonic() + _DEPLOY_TIMEOUT
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"'{self._n('management_host')}' did not reach ACTIVE within timeout.")
                time.sleep(_POLL_INTERVAL)
                current = self._conn.compute.get_server(server.id)
                if current.status == "ACTIVE":
                    self._log_instance_info(self._n("management_host"), current, flavor, image)
                    break
                elif current.status == "ERROR":
                    raise RuntimeError(f"'{self._n('management_host')}' entered ERROR: {getattr(current, 'fault', 'unknown')}")

            ext_net = self._conn.network.find_network("external")
            if not ext_net:
                raise RuntimeError("External network 'external' not found.")
            time.sleep(1)
            fip = self._conn.network.create_ip(floating_network_id=ext_net.id)
            time.sleep(1)
            port = next(iter(self._conn.network.ports(device_id=server.id, network_id=os_mgmt_net.id)))
            self._conn.network.update_ip(fip.id, port_id=port.id)
            mgmt_floating_ip = fip.floating_ip_address
            logger.info("Assigned floating IP %s to management_host", mgmt_floating_ip)

        hosts = topology.get_all_hosts()
        for i in range(0, len(hosts), _BATCH_SIZE):
            batch = hosts[i:i + _BATCH_SIZE]
            pending: dict[str, tuple[Host, object, object]] = {}

            for host in batch:
                base_image_name = self._online.get_base_image(host.vm_type)
                image = self._conn.image.find_image(base_image_name)
                if not image:
                    raise RuntimeError(f"Image '{base_image_name}' not found in Glance.")

                flavor = self._conn.compute.find_flavor(host.flavor)
                if not flavor:
                    raise RuntimeError(f"Flavor '{host.flavor}' not found in OpenStack.")

                subnet = topology.get_subnet_for_host(host)
                if not subnet:
                    raise RuntimeError(f"No subnet found for host '{host.name}'.")
                os_net = self._conn.network.find_network(self._n(subnet.name), project_id=self._project_id)
                if not os_net:
                    raise RuntimeError(f"OpenStack network '{self._n(subnet.name)}' not found.")

                network_spec: dict = {"uuid": os_net.id}
                if host.ip_address:
                    network_spec["fixed_ip"] = str(host.ip_address)

                logger.info("Submitting: %s  image=%s  flavor=%s", self._n(host.name), image.name, flavor.name)
                time.sleep(1)
                server = self._conn.compute.create_server(
                    name=self._n(host.name),
                    imageRef=image.id,
                    flavorRef=flavor.id,
                    networks=[network_spec],
                    security_groups=[{"name": self._n(subnet.sg_name)}],
                    key_name=self._ssh_key_name,
                )
                pending[server.id] = (host, flavor, image)

            deadline = time.monotonic() + _DEPLOY_TIMEOUT
            while pending:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Timed out waiting for: {[h.name for h, _, _ in pending.values()]}")
                time.sleep(_POLL_INTERVAL)
                done = []
                for server_id, (host, flavor, image) in pending.items():
                    current = self._conn.compute.get_server(server_id)
                    if current.status == "ACTIVE":
                        self._log_instance_info(self._n(host.name), current, flavor, image)
                        done.append(server_id)
                    elif current.status == "ERROR":
                        raise RuntimeError(f"Instance '{host.name}' entered ERROR: {getattr(current, 'fault', 'unknown')}")
                for server_id in done:
                    del pending[server_id]

        return mgmt_floating_ip

    def teardown(self, topology: NetworkTopology) -> None:
        if self._management:
            mgmt_name = self._n("management_host")
            for server in self._conn.compute.servers(name=mgmt_name, project_id=self._project_id):
                for port in self._conn.network.ports(device_id=server.id):
                    for fip in self._conn.network.ips(port_id=port.id):
                        self._conn.network.delete_ip(fip.id)
                        logger.info("Released floating IP: %s", fip.floating_ip_address)

        pending: dict[str, str] = {}

        if self._management:
            for server in self._conn.compute.servers(name=self._n("management_host"), project_id=self._project_id):
                self._conn.compute.delete_server(server.id, force=True)
                pending[server.id] = self._n("management_host")
                logger.info("Deleting: %s", self._n("management_host"))

        for host in topology.get_all_hosts():
            matches = list(self._conn.compute.servers(name=self._n(host.name), project_id=self._project_id))
            for server in matches:
                self._conn.compute.delete_server(server.id, force=True)
                pending[server.id] = self._n(host.name)
                logger.info("Deleting: %s", self._n(host.name))

        deadline = time.monotonic() + _DELETE_TIMEOUT
        while pending:
            if time.monotonic() > deadline:
                raise TimeoutError(f"Timed out waiting for deletion of: {list(pending.values())}")
            time.sleep(_POLL_INTERVAL)
            gone = [sid for sid in pending if self._conn.compute.find_server(sid) is None]
            for sid in gone:
                logger.info("Deleted: %s", pending.pop(sid))
