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
