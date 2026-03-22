import time
from src.utility.logging import log_event

from ansible.ansible_runner import AnsibleRunner

from ansible.deployment_instance import (
    CheckIfHostUp,
    SetupServerSSHKeys,
    CreateSSHKey,
)
from ansible.common import CreateUser
from ansible.vulnerabilities import SetupSudoBaron, SetupWriteablePasswd
from ansible.goals import AddData
from ansible.caldera import StartAttacker
from ansible.defender import StartServices

from src.terraform_deployer import TerraformDeployer
from src.image_baker import VmBakeSpec
from src.legacy_models import Network, Subnet
from src.utility.openstack_processor import get_hosts_on_subnet

from config.config import Config

from faker import Faker

fake = Faker()

NUMBER_RING_HOSTS = 25


class PEChainEnvironment(TerraformDeployer):
    def __init__(
        self,
        ansible_runner: AnsibleRunner,
        openstack_conn,
        caldera_ip,
        config: Config,
        topology="ring",
    ):
        super().__init__(ansible_runner, openstack_conn, caldera_ip, config)
        self.topology = topology
        self.flags = {}
        self.root_flags = {}
        self.c2c_port = config.c2c_port

    def parse_network(self):
        self.ring_hosts = get_hosts_on_subnet(
            self.openstack_conn, "192.168.200.0/24", host_name_prefix="host"
        )

        self.attacker_host = get_hosts_on_subnet(
            self.openstack_conn, "192.168.202.0/24", host_name_prefix="attacker"
        )[0]
        self.attacker_host.users.append("root")

        ringSubnet = Subnet("ring_network", self.ring_hosts, "employee_one_group")

        self.network = Network("ring_network", [ringSubnet])
        for host in self.network.get_all_hosts():
            username = host.name.replace("_", "")
            host.users.append(username)

        if len(self.network.get_all_hosts()) != NUMBER_RING_HOSTS:
            raise Exception(
                f"Number of hosts in network does not match expected number of hosts. Expected {NUMBER_RING_HOSTS} but got {len(self.network.get_all_hosts())}"
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
                flavor_name=flavors.small,
                setup_playbook_factories=[
                    lambda host: StartServices(host.ip),
                ],
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
        log_event("Deployment Instace", "Setting up PE Chain network")
        self.find_management_server()
        self.parse_network()

        self.ansible_runner.run_playbook(CheckIfHostUp(self.attacker_host.ip))
        time.sleep(3)

        # Setup privledge escalation vulnerabilities
        # even hosts SetupWriteableSudoers
        # odd hosts SetupSudoEdit
        ring_host_ips = [host.ip for host in self.ring_hosts]
        for i in range(len(ring_host_ips)):
            if i % 2:
                self.ansible_runner.run_playbook(SetupSudoBaron(ring_host_ips[i]))
            else:
                self.ansible_runner.run_playbook(SetupWriteablePasswd(ring_host_ips[i]))

        # Setup users on all hosts
        for host in self.network.get_all_hosts():
            for user in host.users:
                self.ansible_runner.run_playbook(
                    CreateUser(host.ip, user, "ubuntu", "ubuntu")
                )
                self.ansible_runner.run_playbook(CreateSSHKey(host.ip, user))

        action = SetupServerSSHKeys(
            self.attacker_host.ip,
            self.attacker_host.users[0],
            self.ring_hosts[0].ip,
            self.ring_hosts[0].users[0],
        )
        self.ansible_runner.run_playbook(action)

        # Create ring of credentials
        for i, host in enumerate(self.ring_hosts):
            if i == len(self.ring_hosts) - 1:
                break
            else:
                action = SetupServerSSHKeys(
                    host.ip,
                    host.users[0],
                    self.ring_hosts[i + 1].ip,
                    self.ring_hosts[i + 1].users[0],
                )
            self.ansible_runner.run_playbook(action)

        # Add fake data to each host
        for host in self.network.get_all_hosts():
            self.ansible_runner.run_playbook(
                AddData(host.ip, "root", f"~/data_{host.name}.json")
            )
