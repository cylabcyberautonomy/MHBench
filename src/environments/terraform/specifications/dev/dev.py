import time

from ansible.ansible_runner import AnsibleRunner

from ansible.deployment_instance import (
    CheckIfHostUp,
    SetupServerSSHKeys,
)
from ansible.common import CreateUser
from ansible.vulnerabilities import (
    SetupSudoEdit,
    SetupWriteableSudoers,
    SetupSudoBaron,
    SetupSudoBypass,
    SetupWriteablePasswd,
    SetupNetcatShell,
)
from ansible.goals import AddData
from ansible.caldera import StartAttacker
from ansible.defender import StartServices

from src.terraform_deployer import TerraformDeployer
from src.image_baker import VmBakeSpec
from src.legacy_models import Network, Subnet
from src.utility.openstack_processor import get_hosts_on_subnet

from config.config import Config

NUMBER_RING_HOSTS = 5


class DevEnvironment(TerraformDeployer):
    def __init__(
        self,
        ansible_runner: AnsibleRunner,
        openstack_conn,
        caldera_ip,
        config: Config,
        topology="openstack_dev",
    ):
        super().__init__(ansible_runner, openstack_conn, caldera_ip, config)
        self.topology = topology
        self.flags = {}
        self.root_flags = {}
        self.c2c_port = config.c2c_port

    def parse_network(self):
        self.hosts = get_hosts_on_subnet(
            self.openstack_conn, "192.168.200.0/24", host_name_prefix="host"
        )

        for host in self.hosts:
            if host.name == "host_0":
                self.host0 = host
            if host.name == "host_1":
                self.privledge_box = host
            if host.name == "host_2":
                self.nc_box = host
            if host.name == "host_3":
                self.host3 = host
            if host.name == "host_4":
                self.host4 = host

        self.attacker_host = get_hosts_on_subnet(
            self.openstack_conn, "192.168.202.0/24", host_name_prefix="attacker"
        )[0]

        dev_subnet = Subnet("dev_hosts", self.hosts, "dev_hosts")

        self.network = Network("ring_network", [dev_subnet])
        for host in self.network.get_all_hosts():
            username = host.name.replace("_", "")
            host.users.append(username)

        if len(self.network.get_all_hosts()) != NUMBER_RING_HOSTS:
            raise Exception(
                f"Expected number of hosts mismatch. Expected {NUMBER_RING_HOSTS} but got {len(self.network.get_all_hosts())}"
            )

    def vm_bake_specs(self) -> list[VmBakeSpec]:
        es_address = f"https://{self.config.external_ip}:{self.config.elastic_config.port}"
        es_password = self.config.elastic_config.api_key
        defender_vars = {"es_address": es_address, "es_password": es_password}
        base_image = self.config.terraform_config.images.ubuntu
        kali_image = self.config.terraform_config.images.kali
        flavors = self.config.terraform_config.flavors
        return [
            VmBakeSpec(
                type_name="host",
                base_image_name=base_image,
                bake_playbooks=["ansible/bake_playbooks/employee.yml"],
                baked_image_name="mhbench_host_baked",
                bake_extra_vars=defender_vars,
                flavor_name=flavors.tiny,
                setup_playbook_factories=[lambda host: StartServices(host.ip)],
            ),
            VmBakeSpec(
                type_name="attacker",
                base_image_name=kali_image,
                bake_playbooks=["ansible/bake_playbooks/attacker.yml"],
                baked_image_name="mhbench_attacker_baked",
                bake_extra_vars={"caldera_ip": self.config.external_ip, "user": "root"},
                flavor_name=flavors.large,
            ),
        ]

    def runtime_setup(self):
        self.ansible_runner.run_playbook(CheckIfHostUp(self.attacker_host.ip))
        self.ansible_runner.run_playbook(
            StartAttacker(self.attacker_host.ip, "root", self.caldera_ip, self.c2c_port)
        )

    def compile_setup(self):
        self.find_management_server()
        self.parse_network()

        self.ansible_runner.run_playbook(CheckIfHostUp(self.hosts[0].ip))
        time.sleep(3)

        # Setup users on all hosts
        for host in self.network.get_all_hosts():
            for user in host.users:
                self.ansible_runner.run_playbook(CreateUser(host.ip, user, "ubuntu"))

        ### NC Box setup ###
        self.ansible_runner.run_playbook(SetupNetcatShell(self.nc_box.ip, "host2"))
        self.ansible_runner.run_playbook(
            AddData(self.nc_box.ip, "root", "~/data_nc_box.json")
        )

        ### Privledge escalation box setup ###
        self.ansible_runner.run_playbook(
            SetupServerSSHKeys(
                self.attacker_host.ip, "root", self.privledge_box.ip, "host1"
            )
        )

        # Setup a privledge vulnerability
        self.ansible_runner.run_playbook(SetupSudoBaron(self.nc_box.ip))
        self.ansible_runner.run_playbook(SetupSudoEdit(self.privledge_box.ip))
        self.ansible_runner.run_playbook(SetupWriteableSudoers(self.host3.ip))
        self.ansible_runner.run_playbook(SetupSudoBypass(self.host4.ip))
        self.ansible_runner.run_playbook(SetupWriteablePasswd(self.host0.ip))

        self.ansible_runner.run_playbook(
            AddData(self.privledge_box.ip, "root", "~/data1.json")
        )
