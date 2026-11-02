from __future__ import annotations

import json
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from config.config import Config

from src.abstractions.network import NetworkTopology
from src.compilation.offline_registry_service import OfflineRegistryService
from src.deployment.online_registry_service import OnlineRegistryService


class JsonSpecParser:

    def parse(self, path: Path) -> NetworkTopology:
        return NetworkTopology.model_validate(json.loads(path.read_text()))

    def validate(
        self,
        topology: NetworkTopology,
        offline_registry: OfflineRegistryService,
        online_registry: OnlineRegistryService,
        config: Config | None = None,
    ) -> list[str]:
        errors = []
        known = set(offline_registry.list_images()) | set(online_registry.list_images())
        for host in topology.get_all_hosts():
            if host.vm_type not in known:
                errors.append(f"Host '{host.name}': vm_type '{host.vm_type}' not found in any registry.")
        if topology.routing is not None:
            for router in topology.routing.routers:
                host = topology.get_host_by_name(router.host)
                base = online_registry.get_base_image(host.vm_type)
                if (base not in offline_registry.list_images()
                        or "frr_router" not in offline_registry.get_ancestor_chain(base)):
                    errors.append(f"Router {host.name!r} needs an image derived from frr_router.")
            if config is not None:
                errors.extend(self.validate_config(topology, config))
        # TODO: verify images exist in Glance and flavors exist in OpenStack
        return errors

    @staticmethod
    def validate_config(topology: NetworkTopology, config: Config) -> list[str]:
        if topology.routing is None:
            return []
        if config.backend != "openstack":
            return [f"BGP routing is not supported by the {config.backend} backend; use OpenStack."]
        if config.management is None:
            return ["BGP environments require a management host."]
        errors = []
        try:
            management = IPv4Network(config.management.cidr)
            address = IPv4Address(config.management.host_ip)
            if (address not in management or address.is_multicast or address.is_loopback
                    or address.is_unspecified or (management.prefixlen < 31 and address in
                                                {management.network_address, management.broadcast_address})):
                errors.append("Management host IP must be a usable address in its management subnet.")
        except ValueError:
            return ["BGP management configuration requires a valid IPv4 CIDR and host IP."]
        if any(management.overlaps(s.cidr) for s in topology.get_all_subnets()):
            errors.append("Management CIDR must not overlap topology subnets.")
        data = [s.cidr for s in topology.get_all_subnets()
                if s.name in topology.routing.data_subnet_names(topology)]
        if config.c2c:
            try:
                endpoint = IPv4Address(config.c2c.ip)
            except ValueError:
                if not topology.routing.control_routes:
                    errors.append("DNS-named BGP C2 endpoints require explicit control_routes.")
            else:
                if any(endpoint in network for network in data):
                    errors.append("C2 endpoints must be outside the experimental data plane.")
        return errors
