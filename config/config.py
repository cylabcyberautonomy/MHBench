from typing import Literal

from pydantic import BaseModel, Field


class TerraformImages(BaseModel):
    ubuntu: str = "Ubuntu20"
    ubuntu_pip: str = "ubuntu20_pip"
    kali: str = "kali-cloud"


class TerraformFlavors(BaseModel):
    tiny: str = "p2.tiny"
    small: str = "m1.small"
    medium: str = "m2.medium"
    large: str = "m2.large"
    huge: str = "m2.huge"


class TerraformConfig(BaseModel):
    images: TerraformImages = Field(default_factory=TerraformImages)
    flavors: TerraformFlavors = Field(default_factory=TerraformFlavors)

    def to_terraform_vars(self) -> dict:
        return {
            "images": self.images.model_dump(),
            "flavors": self.flavors.model_dump(),
        }


class ElasticSearchConfig(BaseModel):
    api_key: str
    port: int


class C2Config(BaseModel):
    api_key: str
    port: int
    external: bool = False
    python_path: str
    caldera_path: str


class OpenstackConfig(BaseModel):
    ssh_key_name: str
    ssh_key_path: str
    project_name: str
    openstack_username: str
    openstack_password: str
    openstack_region: str
    openstack_auth_url: str
    perry_key_name: str | None = None

    def to_terraform_vars(self) -> dict[str, str]:
        """Render the Terraform variable mapping expected by our modules."""
        perry_key = self.perry_key_name or self.ssh_key_name
        return {
            "project_name": self.project_name,
            "openstack_username": self.openstack_username,
            "openstack_password": self.openstack_password,
            "openstack_region": self.openstack_region,
            "openstack_auth_url": self.openstack_auth_url,
            "perry_key_name": perry_key,
        }


class WebhookConfig(BaseModel):
    url: str
    type: Literal["discord", "slack"]


class Config(BaseModel):
    elastic_config: ElasticSearchConfig
    c2_config: C2Config | None = None
    openstack_config: OpenstackConfig
    terraform_config: TerraformConfig = Field(default_factory=TerraformConfig)
    webhook_config: WebhookConfig | None = None
    external_ip: str
    experiment_timeout_minutes: int
    availability_zone: str = ""  # Nova AZ to pin VMs to (created by Perry per slot)

    @property
    def terraform_vars(self) -> dict:
        """Expose Terraform variables derived from the OpenStack and Terraform configs."""
        return {
            **self.openstack_config.to_terraform_vars(),
            **self.terraform_config.to_terraform_vars(),
            "availability_zone": self.availability_zone,
        }
