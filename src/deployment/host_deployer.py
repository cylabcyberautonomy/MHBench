from __future__ import annotations

import base64
import hashlib
import logging
import os
import subprocess
import tempfile
import time

from openstack.connection import Connection

from config.config import Config
from src.abstractions.network import Host, NetworkTopology
from src.deployment.online_registry_service import OnlineRegistryService

logger = logging.getLogger(__name__)

_BATCH_SIZE = 6   # per-env cap on concurrent same-flavor VM-creates; with the harness provision-gate (5 envs) this bounds global creates to 5*6=30 — the known-safe ceiling (batch 10 * provision 6 = 60 half-provisioned networking -> setup_ssh_keys UNREACHABLE -> whole-env retries)
_DEPLOY_TIMEOUT = 1200  # 20 min. The m2.large attacker's 7.2GB Kali image is pulled from Glance on any node that
                        # doesn't have it cached in _base; under a concurrent-spawn burst that pull can exceed 10 min
                        # and stall the VM in BUILD. Once a node has pulled Kali once, later spawns there are fast
                        # local copies — so this ceiling only bites the FIRST cache-miss per node during a big run.
_DELETE_TIMEOUT = 300
_POLL_INTERVAL = 5
_VM_CREATE_RETRIES = 3  # per-VM recreate attempts on ERROR (NoValidHost during a packing burst) — retry the VM, not the env
_FIP_RECYCLE_ATTEMPTS = 3
_CONSOLE_KEY_TIMEOUT = 120


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
                config_drive=True,  # metadata+network_data off the attached ISO, not the neutron metadata/DHCP agents (concurrency ceiling)
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
            mgmt_floating_ip = self._verify_and_recycle_fip(server, port, ext_net, fip, mgmt_floating_ip)

        all_hosts = topology.get_all_hosts()
        # Create the biggest hosts first — above all the m2.large attacker, which needs the most scheduling/RAM
        # and starves behind a swarm of m1.small VMs otherwise. It also has the SMALLEST image, so the old
        # image-size sort put it dead last (in the most-loaded final batch) — the exact starvation we saw.
        # Flavor size dominates the order; image size is only the tiebreak among equal flavors.
        flavor_ram = {fl: getattr(self._conn.compute.find_flavor(fl), "ram", 0) or 0 for fl in {h.flavor for h in all_hosts}}
        img_size = {vt: getattr(self._conn.image.find_image(self._online.get_base_image(vt)), "size", 0) or 0
                    for vt in {h.vm_type for h in all_hosts}}
        hosts = sorted(all_hosts, key=lambda h: (flavor_ram[h.flavor], img_size[h.vm_type]), reverse=True)
        # Tier the batches by flavor size: a batch never mixes a bigger flavor with smaller ones. We block
        # per batch (wait for ACTIVE), so the m2.large attacker gets its own tier and fully comes up BEFORE
        # the m1.small swarm is even created — otherwise the small hosts, which boot faster, reach ACTIVE first.
        batches: list[list[Host]] = []
        for host in hosts:
            if batches and len(batches[-1]) < _BATCH_SIZE and flavor_ram[batches[-1][0].flavor] == flavor_ram[host.flavor]:
                batches[-1].append(host)
            else:
                batches.append([host])
        vm_retries: dict[str, int] = {}  # per-host recreate count across batches — retry the VM on ERROR, not the whole env
        for batch in batches:
            pending: dict[str, tuple[Host, object, object, dict]] = {}

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

                create_kwargs = dict(
                    name=self._n(host.name),    # OpenStack display label — experiment-prefixed, collision-safe
                    hostname=host.name,         # in-VM hostname — clean DNS-safe host-N, decoupled from the prefix
                    imageRef=image.id,
                    flavorRef=flavor.id,
                    networks=[network_spec],
                    security_groups=[{"name": self._n(subnet.sg_name)}],
                    key_name=self._ssh_key_name,
                    config_drive=True,  # metadata+network_data off the attached ISO, not the neutron metadata/DHCP agents (concurrency ceiling)
                )
                logger.info("Submitting: %s  image=%s  flavor=%s", self._n(host.name), image.name, flavor.name)
                time.sleep(1)
                server = self._conn.compute.create_server(**create_kwargs)  # kept for recreate-on-ERROR
                pending[server.id] = (host, flavor, image, create_kwargs)

            deadline = time.monotonic() + _DEPLOY_TIMEOUT
            while pending:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Timed out waiting for: {[h.name for h, *_ in pending.values()]}")
                time.sleep(_POLL_INTERVAL)
                done = []
                recreated: list[tuple[str, str, tuple]] = []  # (old_id, new_id, pending-value) — applied after the scan
                for server_id, (host, flavor, image, create_kwargs) in pending.items():
                    current = self._conn.compute.get_server(server_id)
                    if current.status == "ACTIVE":
                        self._log_instance_info(self._n(host.name), current, flavor, image)
                        done.append(server_id)
                    elif current.status == "ERROR":
                        # A single VM failing to schedule (NoValidHost during a packing burst) is transient — delete
                        # and recreate JUST this VM rather than raising and forcing a whole-environment retry.
                        n = vm_retries.get(host.name, 0)
                        if n >= _VM_CREATE_RETRIES:
                            raise RuntimeError(f"Instance '{host.name}' entered ERROR after {n} recreate attempts: {getattr(current, 'fault', 'unknown')}")
                        vm_retries[host.name] = n + 1
                        logger.warning("Instance '%s' entered ERROR (%s) — recreating (attempt %d/%d)",
                                       host.name, getattr(current, "fault", "unknown"), n + 1, _VM_CREATE_RETRIES)
                        try:
                            self._conn.compute.delete_server(server_id)
                        except Exception:
                            logger.exception("Failed deleting errored server for '%s' before recreate", host.name)
                        time.sleep(1)
                        new = self._conn.compute.create_server(**create_kwargs)
                        recreated.append((server_id, new.id, (host, flavor, image, create_kwargs)))
                for server_id in done:
                    del pending[server_id]
                for old_id, new_id, val in recreated:
                    del pending[old_id]
                    pending[new_id] = val

        return mgmt_floating_ip

    def _console_host_key(self, server) -> str | None:
        deadline = time.monotonic() + _CONSOLE_KEY_TIMEOUT
        while time.monotonic() < deadline:
            try:
                out = self._conn.compute.get_server_console_output(server)
                text = out.get("output", "") if isinstance(out, dict) else str(out)
            except Exception:
                text = ""
            for line in text.splitlines():
                if "(ED25519)" in line and "SHA256:" in line:
                    return "SHA256:" + line.split("SHA256:")[1].split()[0]
            time.sleep(_POLL_INTERVAL)
        return None

    def _fip_host_key(self, fip_addr: str) -> str | None:
        for _ in range(3):
            fd, khf = tempfile.mkstemp()
            os.close(fd)
            try:
                subprocess.run(
                    ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                     "-o", f"UserKnownHostsFile={khf}", "-o", "ConnectTimeout=8",
                     f"root@{fip_addr}", "true"],
                    capture_output=True, timeout=25)
                for line in open(khf):
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == "ssh-ed25519":
                        digest = hashlib.sha256(base64.b64decode(parts[2])).digest()
                        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
            except Exception:
                pass
            finally:
                try:
                    os.remove(khf)
                except OSError:
                    pass
            time.sleep(_POLL_INTERVAL)
        return None

    def _verify_and_recycle_fip(self, server, port, ext_net, fip, mgmt_floating_ip: str) -> str:
        true_fp = self._console_host_key(server)
        if not true_fp:
            logger.warning("Could not read mgmt host key from console; skipping stale-FIP check for %s", mgmt_floating_ip)
            return mgmt_floating_ip
        for attempt in range(1, _FIP_RECYCLE_ATTEMPTS + 1):
            if self._fip_host_key(mgmt_floating_ip) == true_fp:
                return mgmt_floating_ip
            logger.warning("mgmt FIP %s is stale (host key != %s) — recycling (%d/%d)",
                           mgmt_floating_ip, true_fp, attempt, _FIP_RECYCLE_ATTEMPTS)
            self._conn.network.update_ip(fip.id, port_id=None)
            self._conn.network.delete_ip(fip.id)
            time.sleep(1)
            fip = self._conn.network.create_ip(floating_network_id=ext_net.id)
            time.sleep(1)
            self._conn.network.update_ip(fip.id, port_id=port.id)
            mgmt_floating_ip = fip.floating_ip_address
        if self._fip_host_key(mgmt_floating_ip) == true_fp:
            return mgmt_floating_ip
        raise RuntimeError(f"mgmt FIP host key never matched after {_FIP_RECYCLE_ATTEMPTS} recycles (last {mgmt_floating_ip})")

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
