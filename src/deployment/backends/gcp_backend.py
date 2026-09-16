from __future__ import annotations

import logging
import re
import time
from pathlib import Path

from config.config import Config, GCPConfig
from src.abstractions.network import NetworkTopology
from src.deployment.backends.base import CloudBackend
from src.deployment.online_registry_service import OnlineRegistryService

logger = logging.getLogger(__name__)

_OP_TIMEOUT = 1200       # per-operation wait ceiling (image pull for a big instance can be slow)
_VM_CREATE_RETRIES = 3
_POLL_INTERVAL = 5


def _lazy_compute():
    """Import the GCP SDK lazily so an OpenStack-only install never needs it."""
    try:
        from google.cloud import compute_v1  # noqa: WPS433
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "The Google Cloud backend needs the 'google-cloud-compute' package. "
            "Install it with `uv sync --extra gcp` or "
            "`pip install 'mhbench[gcp]'`."
        ) from exc
    return compute_v1


def _gcp_name(name: str) -> str:
    """Coerce an arbitrary MHBench name into an RFC1035 GCP resource name:
    lowercase, digits and hyphens only, starts with a letter, <=63 chars.
    Deterministic so teardown reconstructs exactly the same name."""
    s = re.sub(r"[^a-z0-9-]", "-", name.lower())
    s = re.sub(r"-+", "-", s).strip("-")
    if not s or not s[0].isalpha():
        s = "m-" + s
    return s[:63].rstrip("-")


class GCPBackend(CloudBackend):
    """Google Cloud provider.

    Topology mapping (OpenStack concept -> GCP concept):
      * router + all networks          -> a single custom-mode VPC network
      * subnet                         -> a regional subnetwork (its CIDR)
      * security group + rules         -> VPC firewall rules targeted by network tag
      * internet egress for private VMs-> a Cloud Router + Cloud NAT
      * management floating IP         -> the management instance's external IP
      * OpenStack flavor / image name  -> GCP machine type / image (via config maps)

    Everything is prefixed by the experiment's ``project_name`` exactly as the
    OpenStack backend prefixes its resources, so concurrent experiments never
    collide and teardown matches purely by name.
    """

    name = "gcp"

    def __init__(self, config: Config, online_registry: OnlineRegistryService, project_name: str | None = None) -> None:
        if config.gcp is None:
            raise ValueError("gcp config block is required for the GCP backend.")
        self._config = config
        self._gcp: GCPConfig = config.gcp
        self._online = online_registry
        self._project_name = project_name
        self._management = config.management

        compute = _lazy_compute()
        self._compute = compute
        client_kwargs = {}
        if self._gcp.credentials_file:
            from google.oauth2 import service_account  # lazy
            client_kwargs["credentials"] = service_account.Credentials.from_service_account_file(
                str(Path(self._gcp.credentials_file).expanduser())
            )
        self._networks = compute.NetworksClient(**client_kwargs)
        self._subnetworks = compute.SubnetworksClient(**client_kwargs)
        self._firewalls = compute.FirewallsClient(**client_kwargs)
        self._routers = compute.RoutersClient(**client_kwargs)
        self._instances = compute.InstancesClient(**client_kwargs)
        self._images = compute.ImagesClient(**client_kwargs)

        self._project = self._gcp.project
        self._region = self._gcp.region
        self._zone = self._gcp.zone

    # -- naming helpers -----------------------------------------------------

    def _n(self, name: str) -> str:
        prefixed = f"{self._project_name}-{name}" if self._project_name else name
        return _gcp_name(prefixed)

    def _net_name(self) -> str:
        return self._n("vpc")

    def _net_url(self) -> str:
        return f"projects/{self._project}/global/networks/{self._net_name()}"

    def _subnet_name(self, subnet_name: str) -> str:
        return self._n(f"{subnet_name}-subnet")

    def _subnet_url(self, subnet_name: str) -> str:
        return f"projects/{self._project}/regions/{self._region}/subnetworks/{self._subnet_name(subnet_name)}"

    @staticmethod
    def _tag(name: str) -> str:
        return _gcp_name(name)

    # -- resolution helpers -------------------------------------------------

    def _machine_type_url(self, flavor: str) -> str:
        mt = self._gcp.machine_type_map.get(flavor, self._gcp.default_machine_type)
        return f"zones/{self._zone}/machineTypes/{mt}"

    def _source_image_url(self, vm_type: str) -> str:
        base = self._online.get_base_image(vm_type)
        mapped = self._gcp.image_map.get(vm_type) or self._gcp.image_map.get(base) or _gcp_name(base)
        img_project = self._gcp.image_project or self._project
        if mapped.startswith("family/"):
            family = mapped.split("/", 1)[1]
            img = self._images.get_from_family(project=img_project, family=family)
            return img.self_link
        return f"projects/{img_project}/global/images/{mapped}"

    def _public_key(self) -> str:
        pub_path = self._gcp.ssh_public_key_path or (self._gcp.ssh_key_path + ".pub")
        return Path(pub_path).expanduser().read_text().strip()

    def _wait(self, operation) -> None:
        """Block on an ExtendedOperation, surfacing GCP errors."""
        operation.result(timeout=_OP_TIMEOUT)
        if getattr(operation, "error_code", None):
            raise RuntimeError(f"GCP operation failed: {operation.error_code} {operation.error_message}")

    # -- networking ---------------------------------------------------------

    def provision_network(self, topology: NetworkTopology) -> None:
        c = self._compute
        logger.info("Creating VPC network '%s'...", self._net_name())
        self._wait(self._networks.insert(project=self._project, network_resource=c.Network(
            name=self._net_name(),
            auto_create_subnetworks=False,
            routing_config=c.NetworkRoutingConfig(routing_mode="REGIONAL"),
        )))

        subnets = list(topology.get_all_subnets())
        # management subnetwork first (mirrors OpenStack ordering)
        if self._management:
            logger.info("Creating management subnetwork...")
            self._wait(self._subnetworks.insert(
                project=self._project, region=self._region,
                subnetwork_resource=c.Subnetwork(
                    name=self._subnet_name("management"),
                    ip_cidr_range=self._management.cidr,
                    network=self._net_url(),
                    region=self._region,
                ),
            ))

        for subnet in subnets:
            logger.info("Creating subnetwork '%s' (%s)...", self._subnet_name(subnet.name), subnet.cidr)
            self._wait(self._subnetworks.insert(
                project=self._project, region=self._region,
                subnetwork_resource=c.Subnetwork(
                    name=self._subnet_name(subnet.name),
                    ip_cidr_range=str(subnet.cidr),
                    network=self._net_url(),
                    region=self._region,
                ),
            ))

        self._create_firewall_rules(topology)
        self._create_nat(topology)

    def _create_firewall_rules(self, topology: NetworkTopology) -> None:
        c = self._compute
        net = self._net_url()

        # Management: allow everything in (it holds the external IP / bastion) — matches OpenStack management_sg.
        if self._management:
            self._insert_firewall(c.Firewall(
                name=self._n("management-ingress"), network=net, direction="INGRESS", priority=1000,
                source_ranges=["0.0.0.0/0"], target_tags=[self._tag(self._n("management"))],
                allowed=[c.Allowed(I_p_protocol="all")],
            ))

        for subnet in topology.get_all_subnets():
            tag = self._tag(self._n(subnet.name))
            if subnet.external:
                # External subnet: reachable from anywhere.
                self._insert_firewall(c.Firewall(
                    name=self._n(f"{subnet.name}-ingress"), network=net, direction="INGRESS", priority=1000,
                    source_ranges=["0.0.0.0/0"], target_tags=[tag],
                    allowed=[c.Allowed(I_p_protocol="all")],
                ))
            else:
                # Internal subnet: own CIDR + peer CIDRs + management CIDR.
                sources = [str(subnet.cidr)]
                peers: set[str] = set()
                for conn in topology.subnet_connections:
                    if conn.from_subnet == subnet.name:
                        peers.add(conn.to_subnet)
                    elif conn.bidirectional and conn.to_subnet == subnet.name:
                        peers.add(conn.from_subnet)
                for peer_name in peers:
                    peer = topology.get_subnet_by_name(peer_name)
                    if peer:
                        sources.append(str(peer.cidr))
                if self._management:
                    sources.append(self._management.cidr)
                self._insert_firewall(c.Firewall(
                    name=self._n(f"{subnet.name}-ingress"), network=net, direction="INGRESS", priority=1000,
                    source_ranges=sorted(set(sources)), target_tags=[tag],
                    allowed=[c.Allowed(I_p_protocol="all")],
                ))
                # Egress: GCP defaults to allow-all egress. Only restrict when the
                # subnet forbids internet egress: allow internal, then deny the rest.
                if not subnet.internet_egress:
                    internal = sorted({str(s.cidr) for s in topology.get_all_subnets()}
                                      | ({self._management.cidr} if self._management else set()))
                    self._insert_firewall(c.Firewall(
                        name=self._n(f"{subnet.name}-egress-internal"), network=net, direction="EGRESS", priority=1000,
                        destination_ranges=internal, target_tags=[tag],
                        allowed=[c.Allowed(I_p_protocol="all")],
                    ))
                    self._insert_firewall(c.Firewall(
                        name=self._n(f"{subnet.name}-egress-deny"), network=net, direction="EGRESS", priority=65534,
                        destination_ranges=["0.0.0.0/0"], target_tags=[tag],
                        denied=[c.Denied(I_p_protocol="all")],
                    ))

    def _insert_firewall(self, firewall) -> None:
        logger.info("Creating firewall rule '%s'...", firewall.name)
        self._wait(self._firewalls.insert(project=self._project, firewall_resource=firewall))

    def _create_nat(self, topology: NetworkTopology) -> None:
        # Private instances (everything but the management host) have no external IP;
        # a Cloud Router + Cloud NAT gives them outbound internet for apt/pip, matching
        # OpenStack SNAT. Only NAT the subnetworks whose subnet allows internet egress.
        c = self._compute
        egress_subnets = [s for s in topology.get_all_subnets() if s.internet_egress]
        if not egress_subnets and not self._management:
            return
        nat_subnets = [
            c.RouterNatSubnetworkToNat(name=self._subnet_url(s.name), source_ip_ranges_to_nat=["ALL_IP_RANGES"])
            for s in egress_subnets
        ]
        if self._management:
            nat_subnets.append(c.RouterNatSubnetworkToNat(
                name=self._subnet_url("management"), source_ip_ranges_to_nat=["ALL_IP_RANGES"],
            ))
        nat = c.RouterNat(
            name=self._n("nat"),
            nat_ip_allocate_option="AUTO_ONLY",
            source_subnetwork_ip_ranges_to_nat="LIST_OF_SUBNETWORKS",
            subnetworks=nat_subnets,
        )
        logger.info("Creating Cloud Router + NAT for private egress...")
        self._wait(self._routers.insert(
            project=self._project, region=self._region,
            router_resource=c.Router(name=self._n("router"), network=self._net_url(), nats=[nat]),
        ))

    def teardown_network(self, topology: NetworkTopology) -> None:
        # Reverse order: router, firewalls, subnetworks, network. Missing == fine.
        self._delete(lambda: self._routers.delete(project=self._project, region=self._region, router=self._n("router")),
                     f"router {self._n('router')}")
        fw_names = []
        if self._management:
            fw_names.append(self._n("management-ingress"))
        for subnet in topology.get_all_subnets():
            fw_names.append(self._n(f"{subnet.name}-ingress"))
            if not subnet.internet_egress:  # only these were created (see _create_firewall_rules)
                fw_names += [self._n(f"{subnet.name}-egress-internal"),
                             self._n(f"{subnet.name}-egress-deny")]
        for fw in fw_names:
            self._delete(lambda fw=fw: self._firewalls.delete(project=self._project, firewall=fw), f"firewall {fw}")

        sub_names = [self._subnet_name(s.name) for s in topology.get_all_subnets()]
        if self._management:
            sub_names.append(self._subnet_name("management"))
        for sn in sub_names:
            self._delete(lambda sn=sn: self._subnetworks.delete(project=self._project, region=self._region, subnetwork=sn),
                         f"subnetwork {sn}")

        self._delete(lambda: self._networks.delete(project=self._project, network=self._net_name()),
                     f"network {self._net_name()}")

    def _delete(self, fn, label: str) -> None:
        from google.api_core.exceptions import NotFound  # lazy
        try:
            self._wait(fn())
            logger.info("Deleted %s", label)
        except NotFound:
            logger.debug("%s already gone", label)
        except Exception:
            logger.exception("Failed deleting %s (continuing teardown)", label)

    # -- hosts --------------------------------------------------------------

    def _build_instance(self, name: str, host_name: str, vm_type: str, flavor: str,
                        subnet_name: str, subnet_tag: str, fixed_ip: str | None, external: bool):
        c = self._compute
        pub = self._public_key()
        ssh_meta = f"{self._gcp.ssh_user}:{pub}"
        if self._gcp.ssh_user != "root":
            ssh_meta += f"\nroot:{pub}"

        nic = c.NetworkInterface(subnetwork=self._subnet_url(subnet_name))
        if fixed_ip:
            nic.network_i_p = fixed_ip
        if external:
            nic.access_configs = [c.AccessConfig(name="External NAT", type_="ONE_TO_ONE_NAT")]

        return c.Instance(
            name=name,
            # clean in-VM hostname (host-N.mhbench.internal), decoupled from the prefixed provider label
            hostname=f"{_gcp_name(host_name)}.mhbench.internal",
            machine_type=self._machine_type_url(flavor),
            tags=c.Tags(items=[subnet_tag]),
            disks=[c.AttachedDisk(
                boot=True, auto_delete=True,
                initialize_params=c.AttachedDiskInitializeParams(source_image=self._source_image_url(vm_type)),
            )],
            network_interfaces=[nic],
            metadata=c.Metadata(items=[
                c.Items(key="ssh-keys", value=ssh_meta),
                c.Items(key="enable-oslogin", value="FALSE"),
            ]),
        )

    def _create_instance_with_retry(self, instance) -> None:
        from google.api_core.exceptions import GoogleAPICallError  # lazy
        for attempt in range(1, _VM_CREATE_RETRIES + 1):
            try:
                self._wait(self._instances.insert(project=self._project, zone=self._zone, instance_resource=instance))
                return
            except (GoogleAPICallError, RuntimeError) as exc:
                if attempt >= _VM_CREATE_RETRIES:
                    raise
                logger.warning("Instance '%s' create failed (%s) — retry %d/%d",
                               instance.name, exc, attempt, _VM_CREATE_RETRIES)
                # a half-created instance blocks the retry; best-effort delete first
                self._delete(lambda: self._instances.delete(project=self._project, zone=self._zone, instance=instance.name),
                             f"errored instance {instance.name}")
                time.sleep(_POLL_INTERVAL)

    def provision_hosts(self, topology: NetworkTopology) -> str | None:
        mgmt_public_ip: str | None = None

        if self._management:
            mgmt = self._management
            name = self._n("management-host")
            logger.info("Creating management host '%s'...", name)
            instance = self._build_instance(
                name=name, host_name="management-host", vm_type=mgmt.vm_type, flavor=mgmt.flavor,
                subnet_name="management", subnet_tag=self._tag(self._n("management")),
                fixed_ip=mgmt.host_ip, external=True,
            )
            self._create_instance_with_retry(instance)
            got = self._instances.get(project=self._project, zone=self._zone, instance=name)
            mgmt_public_ip = got.network_interfaces[0].access_configs[0].nat_i_p
            logger.info("Management host external IP: %s", mgmt_public_ip)

        for host in topology.get_all_hosts():
            subnet = topology.get_subnet_for_host(host)
            if not subnet:
                raise RuntimeError(f"No subnet found for host '{host.name}'.")
            name = self._n(host.name)
            logger.info("Creating host '%s' (flavor=%s, vm_type=%s)...", name, host.flavor, host.vm_type)
            instance = self._build_instance(
                name=name, host_name=host.name, vm_type=host.vm_type, flavor=host.flavor,
                subnet_name=subnet.name, subnet_tag=self._tag(self._n(subnet.name)),
                fixed_ip=str(host.ip_address) if host.ip_address else None,
                external=False,
            )
            self._create_instance_with_retry(instance)

        return mgmt_public_ip

    def teardown_hosts(self, topology: NetworkTopology) -> None:
        names = [self._n(h.name) for h in topology.get_all_hosts()]
        if self._management:
            names.append(self._n("management-host"))
        for name in names:
            self._delete(lambda name=name: self._instances.delete(project=self._project, zone=self._zone, instance=name),
                         f"instance {name}")

    # -- Ansible support ----------------------------------------------------

    def get_console_output(self, host_full_name: str, length: int | None = None) -> str | None:
        # host_full_name is already project-prefixed by the caller, but not yet
        # GCP-sanitized; run it through the same coercion the instances got.
        name = _gcp_name(host_full_name)
        try:
            out = self._instances.get_serial_port_output(project=self._project, zone=self._zone, instance=name)
            text = out.contents or ""
            if length:
                text = "\n".join(text.splitlines()[-length:])
            return text
        except Exception:
            logger.exception("Failed to fetch serial console for '%s'", name)
            return None

    # -- images -------------------------------------------------------------

    def upload_image(self, name: str, location: str, force: bool = False) -> None:
        """Import a compiled qcow2 as a GCP image.

        GCP images are not qcow2 in Glance; a raw ``disk.raw`` is tarred, staged in
        Cloud Storage, then registered via images.insert(raw_disk.source=gs://...).
        Requires ``gcp.image_bucket`` and the qemu-img tool. This mirrors what
        ``gcloud compute images import`` does, without the extra Cloud Build step.
        """
        import subprocess
        import tarfile
        import tempfile

        c = self._compute
        img_name = self._gcp.image_map.get(name, _gcp_name(name))
        if not location or not Path(location).exists():
            logger.warning("'%s' is not compiled at %s — skipping upload.", name, location)
            return
        if not self._gcp.image_bucket:
            raise RuntimeError(
                "gcp.image_bucket must be set to upload images. Alternatively import the "
                "qcow2 out of band with `gcloud compute images import` and map it via gcp.image_map."
            )

        existing = None
        from google.api_core.exceptions import NotFound  # lazy
        try:
            existing = self._images.get(project=self._project, image=img_name)
        except NotFound:
            existing = None
        if existing and not force:
            logger.info("Image '%s' already exists — skipping (use force to re-import).", img_name)
            return
        if existing and force:
            self.delete_image(name)

        try:
            from google.cloud import storage  # lazy
        except ImportError as exc:
            raise RuntimeError("Image upload needs 'google-cloud-storage' (pip install google-cloud-storage).") from exc

        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "disk.raw"
            logger.info("Converting %s -> raw...", location)
            subprocess.run(["qemu-img", "convert", "-f", "qcow2", "-O", "raw", location, str(raw)], check=True)
            tar_path = Path(tmp) / f"{img_name}.tar.gz"
            logger.info("Packing %s...", tar_path.name)
            with tarfile.open(tar_path, "w:gz") as tf:
                tf.add(raw, arcname="disk.raw")

            storage_client = (storage.Client.from_service_account_json(self._gcp.credentials_file)
                              if self._gcp.credentials_file else storage.Client(project=self._project))
            bucket = storage_client.bucket(self._gcp.image_bucket)
            blob_name = f"mhbench-images/{img_name}.tar.gz"
            logger.info("Uploading to gs://%s/%s ...", self._gcp.image_bucket, blob_name)
            bucket.blob(blob_name).upload_from_filename(str(tar_path))

            logger.info("Registering image '%s'...", img_name)
            self._wait(self._images.insert(project=self._project, image_resource=c.Image(
                name=img_name,
                raw_disk=c.RawDisk(source=f"https://storage.googleapis.com/{self._gcp.image_bucket}/{blob_name}"),
            )))
        logger.info("Imported image '%s'.", img_name)

    def delete_image(self, name: str) -> None:
        from google.api_core.exceptions import NotFound  # lazy
        img_name = self._gcp.image_map.get(name, _gcp_name(name))
        try:
            self._wait(self._images.delete(project=self._project, image=img_name))
            logger.info("Deleted image '%s'.", img_name)
        except NotFound:
            logger.warning("Image '%s' not found — nothing to delete.", img_name)
