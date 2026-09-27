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
        # Build credentials once and share them across every client (Compute here, Storage in
        # upload_image). None -> Application Default Credentials.
        self._credentials = None
        client_kwargs = {}
        if self._gcp.credentials_file:
            from google.oauth2 import service_account  # lazy
            self._credentials = service_account.Credentials.from_service_account_file(
                str(Path(self._gcp.credentials_file).expanduser())
            )
            client_kwargs["credentials"] = self._credentials
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

    def _inst(self, name: str) -> str:
        """Instance name — deliberately NOT experiment-prefixed, unlike _n(). GCP's internal DNS
        serves a reverse (PTR) record built from the instance name, which the attacker resolves during
        recon: an experiment-prefixed instance name (e.g. gcp-eqs-opus46-shell-staticall-t0-webserver0)
        would hand the attacker the whole benchmark config. The plain topology name (webserver0) reads
        like an ordinary host, matching the guest hostname. This is safe ONLY because GCP experiments
        run SEQUENTIALLY (config.gcp.yaml max_active_experiments=1), so plain names are unique per zone;
        teardown_hosts deletes by the same _inst() name and _sweep_vpc() catches anything left over.
        Network resources (VPC/subnet/firewall/router) keep _n() — they are not attacker-visible and
        the decoy's subnet lookup depends on the experiment-prefixed subnet name."""
        return _gcp_name(name)

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

        # Sweep anything still attached to this VPC that the topology teardown above did not own:
        # defender decoy VMs and the harness-created C2 host, plus any of their firewalls. They are
        # created outside MHBench's ledger but live in MHBench's dedicated per-experiment VPC, so if
        # left behind they pin the subnetwork/VPC deletes below (best-effort => silent) and strand the
        # whole network, with the decoy vCPUs still counting against the global CPU quota. The VPC is
        # exclusive to this experiment, so deleting everything remaining in it is safe.
        self._sweep_vpc()

        sub_names = [self._subnet_name(s.name) for s in topology.get_all_subnets()]
        if self._management:
            sub_names.append(self._subnet_name("management"))
        for sn in sub_names:
            self._delete(lambda sn=sn: self._subnetworks.delete(project=self._project, region=self._region, subnetwork=sn),
                         f"subnetwork {sn}")

        self._delete(lambda: self._networks.delete(project=self._project, network=self._net_name()),
                     f"network {self._net_name()}")

    def _sweep_vpc(self) -> None:
        """Delete every instance and firewall still attached to this experiment's VPC. Called during
        teardown to clear resources created outside MHBench's topology ledger (defender decoys, the
        harness C2 and its firewalls) that would otherwise pin the subnetwork/VPC delete. Matches by
        network membership (not name), so it catches decoys under any naming scheme. Best-effort."""
        net_suffix = f"/networks/{self._net_name()}"
        try:
            for inst in self._instances.list(project=self._project, zone=self._zone):
                if any((nic.network or "").endswith(net_suffix) for nic in inst.network_interfaces):
                    self._delete(lambda n=inst.name: self._instances.delete(
                        project=self._project, zone=self._zone, instance=n), f"stray instance {inst.name}")
        except Exception:
            logger.exception("VPC instance sweep failed for %s (continuing teardown)", self._net_name())
        try:
            for fw in self._firewalls.list(project=self._project):
                if (fw.network or "").endswith(net_suffix):
                    self._delete(lambda n=fw.name: self._firewalls.delete(
                        project=self._project, firewall=n), f"stray firewall {fw.name}")
        except Exception:
            logger.exception("VPC firewall sweep failed for %s (continuing teardown)", self._net_name())

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

        # cloud-init's GCE datasource honors metadata `ssh-keys` only for the default
        # user (ubuntu) and ignores a `root:` entry, but MHBench connects as root. The
        # OpenStack-built images carry no google-guest-agent, so the only reliable way
        # to authorize root is cloud-init user-data, which the GCE datasource DOES run.
        # This also (re)creates the `ubuntu` user the topology plays operate on.
        user_data = (
            "#cloud-config\n"
            "disable_root: false\n"
            "runcmd:\n"
            "  - install -d -m700 /root/.ssh\n"
            f"  - echo '{pub}' >> /root/.ssh/authorized_keys\n"
            "  - chmod 600 /root/.ssh/authorized_keys\n"
            "  - id ubuntu >/dev/null 2>&1 || useradd -m -s /bin/bash ubuntu\n"
            "  - install -d -m700 -o ubuntu -g ubuntu /home/ubuntu/.ssh\n"
            f"  - echo '{pub}' >> /home/ubuntu/.ssh/authorized_keys\n"
            "  - chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys\n"
            "  - chmod 600 /home/ubuntu/.ssh/authorized_keys\n"
        )

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
                c.Items(key="user-data", value=user_data),
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
        # Build every instance spec up front (management first so we can return its external IP).
        specs: list[tuple[str, object]] = []
        if self._management:
            mgmt = self._management
            mname = self._inst("management-host")
            specs.append((mname, self._build_instance(
                name=mname, host_name="management-host", vm_type=mgmt.vm_type, flavor=mgmt.flavor,
                subnet_name="management", subnet_tag=self._tag(self._n("management")),
                fixed_ip=mgmt.host_ip, external=True,
            )))
        for host in topology.get_all_hosts():
            subnet = topology.get_subnet_for_host(host)
            if not subnet:
                raise RuntimeError(f"No subnet found for host '{host.name}'.")
            hname = self._inst(host.name)
            specs.append((hname, self._build_instance(
                name=hname, host_name=host.name, vm_type=host.vm_type, flavor=host.flavor,
                subnet_name=subnet.name, subnet_tag=self._tag(self._n(subnet.name)),
                fixed_ip=str(host.ip_address) if host.ip_address else None, external=False,
            )))

        # Create every VM CONCURRENTLY. Unlike OpenStack (whose shared bastion sshd, Neutron control
        # plane and floating-IP pool force batching), GCP's Compute API is built for concurrent inserts
        # and quota already admits the whole env — so submit all inserts at once, then wait, and each
        # VM's create runs in parallel server-side. A failed VM is retried individually.
        logger.info("Submitting %d instances concurrently...", len(specs))
        instmap = {n: i for n, i in specs}
        ops = {n: self._instances.insert(project=self._project, zone=self._zone, instance_resource=i)
               for n, i in specs}
        for name in list(ops):
            attempt = 0
            while True:
                try:
                    self._wait(ops[name])
                    break
                except Exception as exc:
                    attempt += 1
                    if attempt > _VM_CREATE_RETRIES:
                        raise RuntimeError(f"Instance '{name}' failed after {attempt} attempts: {exc}")
                    logger.warning("Instance '%s' failed (%s) — recreating (attempt %d/%d)",
                                   name, exc, attempt, _VM_CREATE_RETRIES)
                    self._delete(lambda name=name: self._instances.delete(
                        project=self._project, zone=self._zone, instance=name), f"errored instance {name}")
                    time.sleep(_POLL_INTERVAL)
                    ops[name] = self._instances.insert(
                        project=self._project, zone=self._zone, instance_resource=instmap[name])
        logger.info("All %d instances ACTIVE", len(specs))

        if self._management:
            got = self._instances.get(project=self._project, zone=self._zone, instance=self._inst("management-host"))
            ip = got.network_interfaces[0].access_configs[0].nat_i_p
            logger.info("Management host external IP: %s", ip)
            return ip
        return None

    def teardown_hosts(self, topology: NetworkTopology) -> None:
        names = [self._inst(h.name) for h in topology.get_all_hosts()]
        if self._management:
            names.append(self._inst("management-host"))
        for name in names:
            self._delete(lambda name=name: self._instances.delete(project=self._project, zone=self._zone, instance=name),
                         f"instance {name}")

    # -- Ansible support ----------------------------------------------------

    def get_console_output(self, host_full_name: str, length: int | None = None) -> str | None:
        # The caller passes "{project}-{host}", but GCP instance names are now the plain host name
        # (see _inst(): the experiment prefix is dropped so reverse DNS doesn't leak the config), so
        # strip the project prefix before looking the instance up.
        name = host_full_name
        if self._project_name and name.startswith(f"{self._project_name}-"):
            name = name[len(self._project_name) + 1:]
        name = _gcp_name(name)
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
            # GCP requires disk.raw to be a whole number of GiB; pad (sparse, free) if the image isn't.
            gib = 1 << 30
            size = raw.stat().st_size
            if size % gib:
                padded = ((size // gib) + 1) * gib
                logger.info("Padding raw disk %d -> %d bytes (whole GiB)", size, padded)
                subprocess.run(["qemu-img", "resize", "-f", "raw", str(raw), str(padded)], check=True)
            tar_path = Path(tmp) / f"{img_name}.tar.gz"
            logger.info("Packing %s...", tar_path.name)
            # GCP's importer only accepts the archive gcloud produces: GNU tar, oldgnu format, sparse.
            # Python's tarfile writes PAX headers by default, which it rejects (INVALID_IMAGE_TAR). Sparse
            # mode also skips the zero holes, so this is much faster than streaming the full raw size.
            subprocess.run(["tar", "--format=oldgnu", "-S", "-czf", str(tar_path), "-C", tmp, "disk.raw"], check=True)

            # Same credentials as the Compute clients (already ~-expanded); None -> ADC.
            storage_client = storage.Client(project=self._project, credentials=self._credentials)
            bucket = storage_client.bucket(self._gcp.image_bucket)
            blob_name = f"mhbench-images/{img_name}.tar.gz"
            logger.info("Uploading to gs://%s/%s ...", self._gcp.image_bucket, blob_name)
            bucket.blob(blob_name).upload_from_filename(str(tar_path))

            logger.info("Registering image '%s'...", img_name)
            self._wait(self._images.insert(project=self._project, image_resource=c.Image(
                name=img_name,
                raw_disk=c.RawDisk(source=f"https://storage.googleapis.com/{self._gcp.image_bucket}/{blob_name}"),
            )))
            # The image is self-contained once registered; drop the staged tarball so it stops costing storage.
            try:
                bucket.blob(blob_name).delete()
                logger.info("Removed staged gs://%s/%s", self._gcp.image_bucket, blob_name)
            except Exception:
                logger.warning("Image registered but could not remove staged gs://%s/%s", self._gcp.image_bucket, blob_name)
        logger.info("Imported image '%s'.", img_name)

    def delete_image(self, name: str) -> None:
        from google.api_core.exceptions import NotFound  # lazy
        img_name = self._gcp.image_map.get(name, _gcp_name(name))
        try:
            self._wait(self._images.delete(project=self._project, image=img_name))
            logger.info("Deleted image '%s'.", img_name)
        except NotFound:
            logger.warning("Image '%s' not found — nothing to delete.", img_name)
