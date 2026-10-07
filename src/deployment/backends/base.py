from __future__ import annotations

from abc import ABC, abstractmethod

from src.abstractions.network import NetworkTopology


class CloudBackend(ABC):
    """Provider-agnostic contract the orchestrator drives.

    MHBench originally spoke the OpenStack SDK directly from every deployer. This
    interface is the seam that lets a second provider (Google Cloud) plug in
    without the orchestrator, the Ansible runner, or the CLI knowing which cloud
    is underneath. Each backend owns its own SDK client(s) and its own naming /
    prefixing, and is responsible for building resources whose *observable shape*
    matches what the rest of MHBench assumes:

      * every host in the topology is reachable on TCP/22 at its spec ``ip_address``
        from the management host, and
      * ``provision_hosts`` returns a single public IP for the management host
        (the bastion every Ansible play ProxyJumps through) — or ``None`` when the
        topology declares no management host.

    Implementations must be idempotent-friendly on teardown (a missing resource is
    not an error) so a partially-provisioned environment can always be cleaned up.
    """

    #: short provider identifier, e.g. ``"openstack"`` / ``"gcp"``
    name: str = "cloud"

    # -- runtime ingress (defender-requested ports) -------------------------

    def add_management_ingress(self, port: int, sources: list[str]) -> None:
        """Open tcp/<port> on the management host from <sources> (victim CIDRs). Used by
        `request-ingress` when a defender asks the environment to forward a server-mediated port
        (e.g. Velociraptor :8000) through the mgmt host to its box. Default: no-op — a backend whose
        management ingress is already open (GCP's is 0.0.0.0/0) needs nothing here."""
        import logging
        logging.getLogger(__name__).info(
            "add_management_ingress: no-op for backend %r (tcp/%d already reachable)", self.name, port)

    # -- per-host dynamic ops (defender-driven topology mutation) ------------
    # Single-host create/rebuild/delete for the arena's dynamic topology interface (a running defender
    # asking the environment to add a decoy / rebuild a compromised host / remove one). NOT abstract:
    # default to unsupported so a backend without single-host provisioning (e.g. GCP's image constraints)
    # simply doesn't implement them and the arena surfaces EnvRequestUnsupported.

    def create_host(self, host, subnet) -> str:
        """Create ONE host on an existing topology subnet; return its fixed IP (no public IP)."""
        raise NotImplementedError(f"{self.name} backend does not support create_host")

    def rebuild_host(self, display_name: str) -> None:
        """Rebuild one existing host from the image it booted from (restore to pristine)."""
        raise NotImplementedError(f"{self.name} backend does not support rebuild_host")

    def remove_host(self, display_name: str) -> None:
        """Delete one existing host."""
        raise NotImplementedError(f"{self.name} backend does not support remove_host")

    # -- provisioning -------------------------------------------------------

    @abstractmethod
    def provision_network(self, topology: NetworkTopology) -> None:
        """Create networks, subnets, routing and firewalling for ``topology``."""

    @abstractmethod
    def provision_hosts(self, topology: NetworkTopology) -> str | None:
        """Create every VM (management host first) and return the management
        host's public IP, or ``None`` if the topology has no management host."""

    @abstractmethod
    def teardown_hosts(self, topology: NetworkTopology) -> None:
        """Delete every VM created for ``topology`` (and release its public IP)."""

    @abstractmethod
    def teardown_network(self, topology: NetworkTopology) -> None:
        """Delete the networks, subnets, routing and firewalling for ``topology``."""

    # -- Ansible support ----------------------------------------------------

    @abstractmethod
    def get_console_output(self, host_full_name: str, length: int | None = None) -> str | None:
        """Return the serial/console log for a host by its provider display name
        (already project-prefixed), or ``None`` if it cannot be fetched. Used only
        for diagnostics when a play fails; never on the happy path."""

    # -- image management ---------------------------------------------------

    @abstractmethod
    def upload_image(self, name: str, location: str, force: bool = False) -> None:
        """Publish a compiled local image so hosts can boot from it."""

    @abstractmethod
    def delete_image(self, name: str) -> None:
        """Delete a previously uploaded image."""
