from pathlib import Path

import yaml
from pydantic import BaseModel

CONFIG_PATH = Path("config/config.yaml")


class CompilationConfig(BaseModel):
    images_dir: Path


class RegistryConfig(BaseModel):
    path: Path


class Config(BaseModel):
    compilation: CompilationConfig
    registry: RegistryConfig

    @classmethod
    def load(cls, config_path: Path = CONFIG_PATH) -> "Config":
        return cls(**yaml.safe_load(config_path.read_text()))
