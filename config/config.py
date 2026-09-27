from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel

CONFIG_PATH = Path("config/config.yaml")


class CompilationConfig(BaseModel):
    images_dir: Path


class RegistryConfig(BaseModel):
    registry_dir: Path


class PlaybooksConfig(BaseModel):
    playbooks_dir: Path


class OpenStackConfig(BaseModel):
    model_config = {"extra": "allow"}

    cloud: str = "openstack"
    clouds_yaml: Optional[str] = None
    keypair_name: str
    ssh_key_path: str
    ssh_user: str = "ubuntu"
    floating_ip_pool: Optional[str] = None
    kali_image: Optional[str] = None
    kali_flavor: Optional[str] = None
    external_network: Optional[str] = None


class GCPConfig(BaseModel):
    """Google Cloud backend configuration.

    GCP has no equivalent of OpenStack's pre-registered keypair: the public key is
    injected into instance metadata at create time, so both a public and a private
    key path are needed. ``machine_type_map`` / ``image_map`` translate the
    OpenStack-flavored names that topology specs and the registries still use
    (``m1.small``, ``ubuntu24``) into GCP machine types and image names, so the
    same spec deploys unchanged on either cloud.
    """

    model_config = {"extra": "allow"}

    # Project / placement.
    project: str
    region: str = "us-central1"
    zone: str = "us-central1-a"
    # Credentials for the GCP API. When unset, Application Default Credentials are
    # used (env GOOGLE_APPLICATION_CREDENTIALS, gcloud auth, or the metadata server).
    credentials_file: Optional[str] = None

    # SSH: private key Ansible uses, matching public key injected into VM metadata,
    # and the guest login user MHBench connects as (the compiled images enable root).
    ssh_key_path: str
    ssh_public_key_path: Optional[str] = None
    ssh_user: str = "root"

    # Cloud Storage bucket used to stage disk images during `upload` (image import).
    image_bucket: Optional[str] = None
    # A GCP image family/project to fall back to when a vm_type has no compiled
    # image uploaded yet (e.g. resolve `ubuntu24` against the public ubuntu-os-cloud).
    image_project: Optional[str] = None

    # OpenStack-flavor -> GCP machine-type, and vm_type/base-image -> GCP image name.
    machine_type_map: dict[str, str] = {}
    image_map: dict[str, str] = {}
    # Default machine type for flavors not present in machine_type_map.
    default_machine_type: str = "e2-standard-2"


class ManagementConfig(BaseModel):
    cidr: str
    host_ip: str
    vm_type: str
    flavor: str


class C2CConfig(BaseModel):
    ip: str
    port: int = 8888


class Config(BaseModel):
    compilation: CompilationConfig
    registry: RegistryConfig
    playbooks: PlaybooksConfig
    # Which cloud provisions the VMs. Defaults to openstack so existing configs
    # (which have no `backend` key) keep working unchanged.
    backend: Literal["openstack", "gcp"] = "openstack"
    openstack: Optional[OpenStackConfig] = None
    gcp: Optional[GCPConfig] = None
    management: Optional[ManagementConfig] = None
    c2c: Optional[C2CConfig] = None
    attacker_play: Optional[str] = None
    attacker_only: bool = False
    ansible_verbosity: int = 0

    @property
    def ssh_key_path(self) -> str:
        """Private SSH key for the active backend (used by the Ansible runner,
        which is otherwise cloud-agnostic)."""
        block = self.active_backend_config()
        if block is None:
            raise ValueError(f"No '{self.backend}' config block; cannot resolve ssh_key_path.")
        return block.ssh_key_path

    @property
    def ssh_user(self) -> str:
        block = self.active_backend_config()
        return getattr(block, "ssh_user", "root") if block is not None else "root"

    def active_backend_config(self) -> Optional[BaseModel]:
        """Return the config block for whichever backend is selected."""
        return self.gcp if self.backend == "gcp" else self.openstack

    @classmethod
    def load(cls, config_path: Path = CONFIG_PATH) -> "Config":
        return cls(**yaml.safe_load(config_path.read_text()))
