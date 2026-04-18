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
    auth_url: str
    username: str
    password: str
    project_name: str
    region: str
    ssh_key_name: str
    ssh_key_path: str
    client_timeout: int = 7200


class Config(BaseModel):
    compilation: CompilationConfig
    registry: RegistryConfig
    playbooks: PlaybooksConfig
    openstack: Optional[OpenStackConfig] = None

    @classmethod
    def load(cls, config_path: Path = CONFIG_PATH) -> "Config":
        return cls(**yaml.safe_load(config_path.read_text()))
