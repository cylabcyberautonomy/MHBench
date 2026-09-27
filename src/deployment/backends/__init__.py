from __future__ import annotations

from config.config import Config
from src.deployment.backends.base import CloudBackend
from src.deployment.online_registry_service import OnlineRegistryService


def build_backend(
    config: Config,
    online_registry: OnlineRegistryService,
    project_name: str | None = None,
) -> CloudBackend:
    """Construct the cloud backend selected by ``config.backend``.

    Backend modules are imported lazily so an OpenStack-only environment never
    needs the GCP SDK installed, and vice versa.
    """
    if config.backend == "gcp":
        from src.deployment.backends.gcp_backend import GCPBackend
        return GCPBackend(config, online_registry, project_name=project_name)
    if config.backend == "openstack":
        from src.deployment.backends.openstack_backend import OpenStackBackend
        return OpenStackBackend(config, online_registry, project_name=project_name)
    raise ValueError(f"Unknown backend '{config.backend}' (expected 'openstack' or 'gcp').")


__all__ = ["CloudBackend", "build_backend"]
