from __future__ import annotations

import logging
import time

from openstack.connection import Connection
from openstack.exceptions import ConflictException

from config.config import Config
from src.abstractions.network import NetworkTopology
from src.deployment.spec_parsers import JsonSpecParser

logger = logging.getLogger(__name__)


class NetworkDeployer:

    def __init__(self, conn: Connection, config: Config, project_name: str | None = None) -> None:
        self._conn = conn
        self._config = config
        self._external_network = (config.openstack.external_network or "external") if config.openstack else "external"
        self._project_id = conn.current_project_id
        self._management = config.management
        self._project_name = project_name

    def _n(self, name: str) -> str:
        return f"{self._project_name}-{name}" if self._project_name else name

    def deploy(self, topology: NetworkTopology) -> None:
        errors = JsonSpecParser.validate_config(topology, self._config)
        if errors:
            raise ValueError("; ".join(errors))
        data_names = topology.routing.data_subnet_names(topology) if topology.routing is not None else set()
        ext_net = self._conn.network.find_network(self._external_network)
        if not ext_net:
            raise RuntimeError(f"External network {self._external_network!r} not found in OpenStack.")

        logger.info("Creating router...")
        router = self._conn.network.create_router(
            name=self._n("router"),
            admin_state_up=True,
            external_gateway_info={"network_id": ext_net.id},
        )
        time.sleep(1)
        deadline = time.monotonic() + 60
        while self._conn.network.get_router(router.id).status != "ACTIVE":
            if time.monotonic() > deadline:
                raise TimeoutError("Router did not reach ACTIVE within 60s.")
            time.sleep(2)
        logger.info("Router ACTIVE")

        # neutron sometimes brings the router up ACTIVE but silently drops the create-time external gateway,
        # leaving it with no SNAT/egress (VMs can't reach the internet; floating IPs don't route). Force it
        # and confirm it attached before proceeding.
        deadline = time.monotonic() + 60
        while not self._conn.network.get_router(router.id).external_gateway_info:
            if time.monotonic() > deadline:
                raise TimeoutError("Router external gateway did not attach within 60s.")
            self._conn.network.update_router(router.id, external_gateway_info={"network_id": ext_net.id})
            time.sleep(3)
        logger.info("Router external gateway attached")

        if self._management:
            mgmt = self._management
            logger.info("Creating management_network...")
            os_mgmt_net = self._conn.network.create_network(name=self._n("management_network"), admin_state_up=True)
            time.sleep(1)
            deadline = time.monotonic() + 60
            while self._conn.network.get_network(os_mgmt_net.id).status != "ACTIVE":
                if time.monotonic() > deadline:
                    raise TimeoutError("Network 'management_network' did not reach ACTIVE within 60s.")
                time.sleep(2)
            logger.info("management_network ACTIVE — creating management_subnet...")
            os_mgmt_subnet = self._conn.network.create_subnet(
                name=self._n("management_subnet"),
                network_id=os_mgmt_net.id,
                ip_version=4,
                cidr=mgmt.cidr,
                enable_dhcp=True,
                dns_nameservers=["8.8.8.8"],
            )
            time.sleep(1)
            logger.info("Attaching management_subnet to router...")
            self._conn.network.add_interface_to_router(router.id, subnet_id=os_mgmt_subnet.id)
            time.sleep(1)
            deadline = time.monotonic() + 60
            while self._conn.network.get_router(router.id).status != "ACTIVE":
                if time.monotonic() > deadline:
                    raise TimeoutError("Router did not return to ACTIVE after attaching 'management_subnet'.")
                time.sleep(2)
            if topology.routing is None:
                logger.info("Router ACTIVE after management_subnet attach — waiting for DHCP agent...")
                deadline = time.monotonic() + 60
                while not list(self._conn.network.network_hosting_dhcp_agents(os_mgmt_net.id)):
                    if time.monotonic() > deadline:
                        raise TimeoutError("DHCP agent did not pick up 'management_network' within 60s.")
                    time.sleep(2)
                logger.info("DHCP agent ready for management_network")

        for subnet in topology.get_all_subnets():
            logger.info("Creating network '%s'...", self._n(subnet.name))
            os_net = self._conn.network.create_network(
                name=self._n(subnet.name),
                admin_state_up=True,
            )
            time.sleep(1)
            deadline = time.monotonic() + 60
            while self._conn.network.get_network(os_net.id).status != "ACTIVE":
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Network '{self._n(subnet.name)}' did not reach ACTIVE within 60s.")
                time.sleep(2)
            logger.info("Network '%s' ACTIVE — creating subnet...", self._n(subnet.name))

            subnet_kwargs = dict(
                name=self._n(f"{subnet.name}-subnet"),
                network_id=os_net.id,
                ip_version=4,
                cidr=str(subnet.cidr),
                enable_dhcp=subnet.name not in data_names,
                dns_nameservers=[] if subnet.name in data_names else subnet.dns_servers,
            )
            if subnet.name in data_names:
                subnet_kwargs["gateway_ip"] = None
            os_subnet = self._conn.network.create_subnet(**subnet_kwargs)
            time.sleep(1)
            if subnet.name in data_names:
                continue  # L2 only: never attach experimental data links to Neutron routing.
            logger.info("Attaching '%s-subnet' to router...", self._n(subnet.name))
            self._conn.network.add_interface_to_router(router.id, subnet_id=os_subnet.id)
            time.sleep(1)
            deadline = time.monotonic() + 60
            while self._conn.network.get_router(router.id).status != "ACTIVE":
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Router did not return to ACTIVE after attaching '{self._n(subnet.name)}'.")
                time.sleep(2)
            if topology.routing is None:
                logger.info("Router ACTIVE after '%s' attach — waiting for DHCP agent...", self._n(subnet.name))
                deadline = time.monotonic() + 60
                while not list(self._conn.network.network_hosting_dhcp_agents(os_net.id)):
                    if time.monotonic() > deadline:
                        raise TimeoutError(f"DHCP agent did not pick up '{self._n(subnet.name)}' within 60s.")
                    time.sleep(2)
                logger.info("DHCP agent ready for '%s'", self._n(subnet.name))

        self._create_security_groups(topology)

    def _new_security_group(self, name: str, description: str):
        sg = self._conn.network.create_security_group(
            name=self._n(name), description=description, stateful=True,
        )
        # Neutron seeds custom groups with rules too. Rebuild only this new group,
        # before any ports use it, so inherited IPv4/IPv6 permissions cannot bypass policy.
        for rule in sg.security_group_rules:
            self._conn.network.delete_security_group_rule(rule["id"])
        return sg

    def _allow(self, sg, direction: str, prefix: str, protocol: str | None = None,
               port: int | None = None) -> None:
        rule = dict(security_group_id=sg.id, direction=direction, ether_type="IPv4",
                    remote_ip_prefix=prefix, protocol=protocol)
        if port is not None:
            rule.update(port_range_min=port, port_range_max=port)
        try:
            self._conn.network.create_security_group_rule(**rule)
        except ConflictException as exc:
            if (exc.response is None or
                    exc.response.json().get("NeutronError", {}).get("type") != "SecurityGroupRuleExists"):
                raise
        time.sleep(1)

    def _create_security_groups(self, topology: NetworkTopology) -> None:
        data_names = topology.routing.data_subnet_names(topology) if topology.routing is not None else set()
        endpoint_lans = {g.subnet for g in topology.routing.host_gateways} if topology.routing is not None else set()
        internal = {str(s.cidr) for s in topology.get_all_subnets() if s.name not in data_names}
        data_prefixes = {str(s.cidr) for s in topology.get_all_subnets() if s.name in data_names}
        management_source = f"{self._management.host_ip}/32" if self._management else None
        if management_source:
            internal.add(management_source)
        for subnet in topology.get_all_subnets():
            is_data = subnet.name in data_names
            if is_data and subnet.name not in endpoint_lans:
                continue  # Router-only data ports have port security disabled, not an unused SG.
            logger.info("Creating security group '%s'...", self._n(subnet.sg_name))
            sg = self._new_security_group(subnet.sg_name, f"Security group for {subnet.name}")
            destinations = data_prefixes if is_data else internal
            for prefix in (["0.0.0.0/0"] if subnet.internet_egress else sorted(destinations)):
                self._allow(sg, "egress", prefix)
            if not subnet.internet_egress and not is_data:
                # OVN does not implicitly permit DHCP discovery broadcasts.
                self._allow(sg, "egress", "255.255.255.255/32", "udp", 67)
            if subnet.external:
                self._allow(sg, "ingress", "0.0.0.0/0")
            else:
                self._allow(sg, "ingress", str(subnet.cidr))
                if management_source and not is_data:
                    # The bastion forwards defender-requested ports on the control plane.
                    self._allow(sg, "ingress", management_source)
                for connection in topology.get_ingress_connections(subnet.name):
                    source = topology.get_subnet_by_name(connection.from_subnet)
                    for port in connection.ports or [None]:
                        self._allow(sg, "ingress", str(source.cidr), connection.protocol, port)
            logger.info("Security group '%s' ready", self._n(subnet.sg_name))

        if self._management:
            mgmt_sg = self._new_security_group("management_sg", "Security group for management network")
            self._allow(mgmt_sg, "egress", "0.0.0.0/0")
            self._allow(mgmt_sg, "ingress", "0.0.0.0/0", "tcp", 22)
            relay_sources = {management_source} | {
                str(s.cidr) for s in topology.get_all_subnets()
                if s.name not in data_names and not s.external
                and s.name not in {"attacker_subnet", "defender_subnet"}
            }
            for prefix in sorted(relay_sources):
                self._allow(mgmt_sg, "ingress", prefix, "tcp", 9200)
            logger.info("Security group '%s' ready", self._n("management_sg"))

    def teardown(self, topology: NetworkTopology) -> None:
        pid = self._project_id

        if self._management:
            for sg in self._conn.network.security_groups(name=self._n("management_sg"), project_id=pid):
                self._conn.network.delete_security_group(sg.id)
                logger.info("Deleted security group: %s", self._n("management_sg"))

        for subnet in topology.get_all_subnets():
            for sg in self._conn.network.security_groups(name=self._n(subnet.sg_name), project_id=pid):
                self._conn.network.delete_security_group(sg.id)
                logger.info("Deleted security group: %s", self._n(subnet.sg_name))

        for router in self._conn.network.routers(name=self._n("router"), project_id=pid):
            for subnet in topology.get_all_subnets():
                if topology.routing is not None and subnet.name in topology.routing.data_subnet_names(topology):
                    continue
                for os_subnet in self._conn.network.subnets(name=self._n(f"{subnet.name}-subnet"), project_id=pid):
                    try:
                        self._conn.network.remove_interface_from_router(router.id, subnet_id=os_subnet.id)
                    except Exception:
                        pass
            if self._management:
                for os_subnet in self._conn.network.subnets(name=self._n("management_subnet"), project_id=pid):
                    try:
                        self._conn.network.remove_interface_from_router(router.id, subnet_id=os_subnet.id)
                    except Exception:
                        pass
            for port in self._conn.network.ports(device_id=router.id, project_id=pid):
                if port.device_owner == "network:router_interface":
                    try:
                        self._conn.network.remove_interface_from_router(router.id, port_id=port.id)
                    except Exception:
                        pass
            self._conn.network.delete_router(router.id)
            logger.info("Deleted router")

        for subnet in topology.get_all_subnets():
            for os_subnet in self._conn.network.subnets(name=self._n(f"{subnet.name}-subnet"), project_id=pid):
                self._conn.network.delete_subnet(os_subnet.id)
                logger.info("Deleted subnet: %s", self._n(f"{subnet.name}-subnet"))

        for subnet in topology.get_all_subnets():
            for os_net in self._conn.network.networks(name=self._n(subnet.name), project_id=pid):
                self._conn.network.delete_network(os_net.id)
                logger.info("Deleted network: %s", self._n(subnet.name))

        if self._management:
            for os_subnet in self._conn.network.subnets(name=self._n("management_subnet"), project_id=pid):
                self._conn.network.delete_subnet(os_subnet.id)
                logger.info("Deleted subnet: %s", self._n("management_subnet"))
            for os_net in self._conn.network.networks(name=self._n("management_network"), project_id=pid):
                self._conn.network.delete_network(os_net.id)
                logger.info("Deleted network: %s", self._n("management_network"))
