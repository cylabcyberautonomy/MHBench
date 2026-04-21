from pathlib import Path
from typing import Optional

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
    openstack: Optional[OpenStackConfig] = None
    management: Optional[ManagementConfig] = None
    c2c: Optional[C2CConfig] = None

    @classmethod
    def load(cls, config_path: Path = CONFIG_PATH) -> "Config":
        return cls(**yaml.safe_load(config_path.read_text()))
