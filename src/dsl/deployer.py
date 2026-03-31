"""
DSLDeployer: deploys a TopologySpec directly to OpenStack.

Fully self-contained — no dependency on the existing OpenStack deployer classes.

Entry points:
  compile(spec, bake_specs, setup_factories_by_type)
      Bake role-specific images, deploy networks + hosts, run setup playbooks.
  deploy(spec, bake_specs, setup_factories_by_type)
      Deploy from baked images and run setup playbooks (skip the slow bake step).

The setup_factories_by_type dict is produced by the VM type registry:
    {"webserver": [lambda host: StartServices(host.ip), ...], ...}
Each factory receives a _SimpleHost(ip, name) and returns an AnsiblePlaybook
(or None to skip).
"""

from __future__ import annotations

import time
from collections import namedtuple
from ipaddress import IPv4Address
from typing import Any, Callable, cast

from openstack.connection import Connection

from ansible.ansible_runner import AnsibleRunner
from config.config import Config
from src.dsl.topology.schema import SubnetSpec, TopologySpec
from src.image_baker import ImageBaker, VmBakeSpec
from src.openstack.cleaner import OpenstackCleaner
from src.terraform_deployer import find_manage_server
from src.utility.logging import get_logger

logger = get_logger()

# Minimal host object passed to setup factories.
_SimpleHost = namedtuple("_SimpleHost", ["ip", "name"])

# Fixed network layout — same values used by the existing deployers.
_MANAGE_CIDR = "192.168.198.0/24"
_MANAGE_HOST_IP = "192.168.198.14"
_MANAGE_HOST_NAME = "manage_host"
_MANAGE_NETWORK_NAME = "manage_network"
_TALK_TO_MANAGE_SG = "talk_to_manage"
_MANAGE_FREEDOM_SG = "manage_freedom"

_ATTACKER_CIDR = "192.168.199.0/24"
_ATTACKER_HOST_IP = "192.168.199.14"
_ATTACKER_HOST_NAME = "attacker_host"
_ATTACKER_NETWORK_NAME = "attacker_network"
_ATTACKER_FREEDOM_SG = "attacker_freedom"

# Image / flavor names — must match what is actually present in Glance/Nova.
_MANAGE_HOST_IMAGE = "mhbench_manage_host_baked"
_ATTACKER_IMAGE = "mhbench_attacker_baked"
_MANAGE_FLAVOR = "p2.tiny"
_ATTACKER_FLAVOR = "m2.large"


class DSLDeployer:
    def __init__(self, config: Config, openstack_conn: Connection) -> None:
        self.config = config
        self.openstack_conn = openstack_conn
        self.project_name = "perry"
        self._router_name = f"{self.project_name}_main_router"

        self._net = cast(Any, openstack_conn.network)
        self._compute = cast(Any, openstack_conn.compute)

        self.cleaner = OpenstackCleaner(openstack_conn)

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def compile(
        self,
        spec: TopologySpec,
        bake_specs: list[VmBakeSpec],
        setup_factories_by_type: dict[str, list[Callable]],
    ) -> None:
        """Bake role-specific images, deploy networks + hosts, run setup playbooks."""
        logger.info(f"[DSL] compile: {spec.name}")

        ImageBaker(self.openstack_conn).bake_all(bake_specs)

        self.cleaner.clean_environment()
        self._deploy_networks(spec)
        self._deploy_management_network()
        self._deploy_attacker_network()
        self._deploy_hosts(spec, bake_specs)
        self._setup_hosts(spec, setup_factories_by_type)

        logger.info(f"[DSL] compile complete: {spec.name}")

    def deploy(
        self,
        spec: TopologySpec,
        bake_specs: list[VmBakeSpec],
        setup_factories_by_type: dict[str, list[Callable]],
    ) -> None:
        """Deploy from baked images and run setup playbooks (skips baking)."""
        logger.info(f"[DSL] deploy: {spec.name}")

        self.cleaner.clean_environment()
        self._deploy_networks(spec)
        self._deploy_management_network()
        self._deploy_attacker_network()
        self._deploy_hosts(spec, bake_specs)
        self._setup_hosts(spec, setup_factories_by_type)

        logger.info(f"[DSL] deploy complete: {spec.name}")

    # ------------------------------------------------------------------
    # Topology networks
    # ------------------------------------------------------------------

    def _deploy_networks(self, spec: TopologySpec) -> None:
        """Create one OS network per DSL subnet, a shared router, and security groups."""
        logger.info("[DSL] Deploying networks...")
        created_os_networks = []

        for subnet_spec in self._all_subnets(spec):
            os_net = self._net.create_network(
                name=subnet_spec.name,
                description=f"Network for {subnet_spec.name} ({subnet_spec.cidr})",
                admin_state_up=True,
            )
            self._net.create_subnet(
                name=f"{subnet_spec.name}_subnet",
                network_id=os_net.id,
                ip_version=4,
                cidr=subnet_spec.cidr,
                enable_dhcp=True,
                dns_nameservers=subnet_spec.dns_servers,
            )
            created_os_networks.append((subnet_spec, os_net))
            logger.info(f"[DSL]   network: {subnet_spec.name} ({subnet_spec.cidr})")

        # Router connecting all subnets to the external network.
        external_net = self._net.find_network("external")
        if not external_net:
            raise RuntimeError("OpenStack 'external' network not found")

        router = self._net.create_router(
            name=self._router_name,
            admin_state_up=True,
            external_gateway_info={"network_id": external_net.id},
        )
        for _, os_net in created_os_networks:
            for os_subnet in self._net.subnets(network_id=os_net.id):
                self._net.add_interface_to_router(
                    router=router.id, subnet_id=os_subnet.id
                )

        # Security groups — one per DSL subnet.
        subnet_cidr_by_name = {s.name: s.cidr for s in self._all_subnets(spec)}
        connection_map = self._build_connection_map(spec)

        for subnet_spec in self._all_subnets(spec):
            sg = self._net.create_security_group(
                name=f"{subnet_spec.name}_sg",
                description=f"Security group for {subnet_spec.name}",
            )
            if subnet_spec.external:
                self._allow_all_tcp(sg.id, "0.0.0.0/0")
            else:
                self._allow_all_tcp(sg.id, subnet_spec.cidr)
                for peer_name in connection_map.get(subnet_spec.name, set()):
                    self._allow_all_tcp(sg.id, subnet_cidr_by_name[peer_name])
            logger.info(f"[DSL]   security group: {subnet_spec.name}_sg")

    def _allow_all_tcp(self, sg_id: str, remote_cidr: str) -> None:
        for direction in ("ingress", "egress"):
            self._net.create_security_group_rule(
                security_group_id=sg_id,
                direction=direction,
                protocol="tcp",
                port_range_min=1,
                port_range_max=65535,
                remote_ip_prefix=remote_cidr,
            )

    def _build_connection_map(self, spec: TopologySpec) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {}
        for conn in spec.subnet_connections:
            result.setdefault(conn.from_subnet, set()).add(conn.to_subnet)
            if conn.bidirectional:
                result.setdefault(conn.to_subnet, set()).add(conn.from_subnet)
        return result

    # ------------------------------------------------------------------
    # Management network
    # ------------------------------------------------------------------

    def _deploy_management_network(self) -> None:
        """Create management network, bastion host, and associated security groups."""
        logger.info("[DSL] Deploying management network...")

        # Security groups.
        talk_sg = self._net.create_security_group(
            name=_TALK_TO_MANAGE_SG,
            description="Allows hosts to be reached by the management bastion",
        )
        for direction in ("ingress", "egress"):
            self._net.create_security_group_rule(
                security_group_id=talk_sg.id,
                direction=direction,
                protocol="tcp",
                port_range_min=22,
                port_range_max=22,
                remote_ip_prefix=_MANAGE_CIDR,
            )

        freedom_sg = self._net.create_security_group(
            name=_MANAGE_FREEDOM_SG,
            description="Full access from the management bastion",
        )
        self._allow_all_tcp(freedom_sg.id, "0.0.0.0/0")

        # Network + subnet.
        mgmt_net = self._net.create_network(
            name=_MANAGE_NETWORK_NAME, admin_state_up=True
        )
        mgmt_subnet = self._net.create_subnet(
            name="manage",
            network_id=mgmt_net.id,
            ip_version=4,
            cidr=_MANAGE_CIDR,
            enable_dhcp=True,
            dns_nameservers=["8.8.8.8"],
        )

        router = self._net.find_router(self._router_name)
        self._net.add_interface_to_router(router=router.id, subnet_id=mgmt_subnet.id)

        # Bastion host.
        instance = self._compute.create_server(
            name=_MANAGE_HOST_NAME,
            imageRef=self._get_image(_MANAGE_HOST_IMAGE).id,
            flavorRef=self._get_flavor(_MANAGE_FLAVOR).id,
            networks=[{"uuid": mgmt_net.id, "fixed_ip": _MANAGE_HOST_IP}],
            security_groups=[
                {"name": _TALK_TO_MANAGE_SG},
                {"name": _MANAGE_FREEDOM_SG},
            ],
            key_name=self.config.openstack_config.ssh_key_name,
        )
        instance = self._compute.wait_for_server(instance, wait=600)

        # Floating IP.
        external_net = self._net.find_network("external")
        floating_ip = self._net.create_ip(floating_network_id=external_net.id)
        port = next(
            (
                p for p in self._net.ports(device_id=instance.id)
                if any(
                    f.get("ip_address") == _MANAGE_HOST_IP
                    for f in p.fixed_ips
                )
            ),
            None,
        )
        if not port:
            raise RuntimeError("Could not find management host port for floating IP")
        self._net.update_ip(floating_ip, port_id=port.id)

        logger.info(
            f"[DSL]   management host ready at {floating_ip.floating_ip_address}"
        )

    # ------------------------------------------------------------------
    # Attacker network
    # ------------------------------------------------------------------

    def _deploy_attacker_network(self) -> None:
        """Create attacker network and Kali host."""
        logger.info("[DSL] Deploying attacker network...")

        # Security group — full TCP/UDP/ICMP access.
        freedom_sg = self._net.create_security_group(
            name=_ATTACKER_FREEDOM_SG,
            description="Full network access for the attacker host",
        )
        self._allow_all_tcp(freedom_sg.id, "0.0.0.0/0")
        for direction in ("ingress", "egress"):
            for protocol in ("udp", "icmp"):
                self._net.create_security_group_rule(
                    security_group_id=freedom_sg.id,
                    direction=direction,
                    protocol=protocol,
                    **({"port_range_min": 1, "port_range_max": 65535} if protocol == "udp" else {}),
                    remote_ip_prefix="0.0.0.0/0",
                )

        # Network + subnet.
        att_net = self._net.create_network(
            name=_ATTACKER_NETWORK_NAME, admin_state_up=True
        )
        att_subnet = self._net.create_subnet(
            name="attacker",
            network_id=att_net.id,
            ip_version=4,
            cidr=_ATTACKER_CIDR,
            enable_dhcp=True,
            dns_nameservers=["8.8.8.8"],
        )

        router = self._net.find_router(self._router_name)
        self._net.add_interface_to_router(router=router.id, subnet_id=att_subnet.id)

        # Attacker host.
        instance = self._compute.create_server(
            name=_ATTACKER_HOST_NAME,
            imageRef=self._get_image(_ATTACKER_IMAGE).id,
            flavorRef=self._get_flavor(_ATTACKER_FLAVOR).id,
            networks=[{"uuid": att_net.id, "fixed_ip": _ATTACKER_HOST_IP}],
            security_groups=[{"name": _ATTACKER_FREEDOM_SG}],
            key_name=self.config.openstack_config.ssh_key_name,
        )
        self._compute.wait_for_server(instance, wait=600)
        logger.info(f"[DSL]   attacker host ready at {_ATTACKER_HOST_IP}")

    # ------------------------------------------------------------------
    # Topology hosts
    # ------------------------------------------------------------------

    def _deploy_hosts(
        self,
        spec: TopologySpec,
        bake_specs: list[VmBakeSpec],
    ) -> None:
        image_by_type = {s.type_name: s.baked_image_name for s in bake_specs}
        flavor_by_type = {
            s.type_name: s.flavor_name for s in bake_specs if s.flavor_name
        }

        talk_sg = self._net.find_security_group(_TALK_TO_MANAGE_SG)
        if not talk_sg:
            raise RuntimeError(f"Security group '{_TALK_TO_MANAGE_SG}' not found")

        pending: list[tuple[str, Any]] = []

        for vm_type, name, ip_str, subnet_name in self._iter_hosts(spec):
            os_net = self._net.find_network(subnet_name)
            if not os_net:
                raise RuntimeError(f"OpenStack network '{subnet_name}' not found")

            network_entry: dict = {"uuid": os_net.id}
            if ip_str:
                network_entry["fixed_ip"] = ip_str

            instance = self._compute.create_server(
                name=name,
                imageRef=self._get_image(image_by_type[vm_type]).id,
                flavorRef=self._get_flavor(flavor_by_type[vm_type]).id,
                networks=[network_entry],
                security_groups=[
                    {"name": f"{subnet_name}_sg"},
                    {"name": talk_sg.name},
                ],
                key_name=self.config.openstack_config.ssh_key_name,
            )
            pending.append((name, instance))
            logger.info(f"[DSL]   submitted: {name}")

        self._wait_for_active(pending)

    def _wait_for_active(
        self,
        instances: list[tuple[str, Any]],
        poll_interval: int = 5,
        max_wait: int = 600,
    ) -> None:
        pending = {inst.id: name for name, inst in instances}
        deadline = time.time() + max_wait

        while pending and time.time() < deadline:
            for inst_id in list(pending):
                server = self._compute.get_server(inst_id)
                if server.status == "ACTIVE":
                    logger.info(f"[DSL]   active: {pending.pop(inst_id)}")
                elif server.status == "ERROR":
                    raise RuntimeError(
                        f"Instance '{pending[inst_id]}' failed: "
                        f"{getattr(server, 'fault', 'unknown error')}"
                    )
            if pending:
                time.sleep(poll_interval)

        if pending:
            raise RuntimeError(
                f"Timeout waiting for instances: {list(pending.values())}"
            )

    # ------------------------------------------------------------------
    # Ansible host setup
    # ------------------------------------------------------------------

    def _setup_hosts(
        self,
        spec: TopologySpec,
        setup_factories_by_type: dict[str, list[Callable]],
    ) -> None:
        _, manage_ip = find_manage_server(self.openstack_conn)
        ansible_runner = AnsibleRunner(
            ssh_key_path=self.config.openstack_config.ssh_key_path,
            management_ip=manage_ip,
            ansible_dir="./ansible/",
            log_path="output",
        )

        for vm_type, name, ip_str, _ in self._iter_hosts(spec):
            if not ip_str:
                continue
            host_obj = _SimpleHost(ip=ip_str, name=name)
            for factory in setup_factories_by_type.get(vm_type, []):
                playbook = factory(host_obj)
                if playbook:
                    ansible_runner.run_playbook(playbook)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _all_subnets(self, spec: TopologySpec) -> list[SubnetSpec]:
        return [s for n in spec.networks for s in n.subnets]

    def _iter_hosts(self, spec: TopologySpec):
        """Yield (vm_type, name, ip_str_or_None, subnet_name) for every host."""
        for network in spec.networks:
            for subnet in network.subnets:
                for group in subnet.host_groups:
                    prefix = group.name_prefix or group.vm_type
                    base_ip = IPv4Address(group.ip_start) if group.ip_start else None
                    for i in range(group.count):
                        ip = str(IPv4Address(int(base_ip) + i)) if base_ip else None
                        yield group.vm_type, f"{prefix}_{i}", ip, subnet.name

    def _get_image(self, name: str) -> Any:
        image = self.openstack_conn.get_image(name)
        if not image:
            raise RuntimeError(f"Image '{name}' not found in Glance")
        return image

    def _get_flavor(self, flavor_name: str) -> Any:
        flavor = self._compute.find_flavor(flavor_name)
        if not flavor:
            raise RuntimeError(f"Flavor '{flavor_name}' not found")
        return flavor
