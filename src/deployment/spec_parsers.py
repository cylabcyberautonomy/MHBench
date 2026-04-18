from __future__ import annotations

import json
from pathlib import Path

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
    ) -> list[str]:
        errors = []
        known = set(offline_registry.list_images()) | set(online_registry.list_images())
        for host in topology.get_all_hosts():
            if host.vm_type not in known:
                errors.append(f"Host '{host.name}': vm_type '{host.vm_type}' not found in any registry.")
        # TODO: verify images exist in Glance and flavors exist in OpenStack
        return errors
