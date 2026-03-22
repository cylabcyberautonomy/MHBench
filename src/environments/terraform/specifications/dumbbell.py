from src.utility.logging import log_event

from ansible.ansible_runner import AnsibleRunner

from ansible.deployment_instance import (
    CheckIfHostUp,
    SetupServerSSHKeys,
    CreateSSHKey,
)
from ansible.common import CreateUser
from ansible.vulnerabilities import SetupStrutsVulnerability
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


class Dumbbell(TerraformDeployer):
    def __init__(
        self,
        ansible_runner: AnsibleRunner,
        openstack_conn,
        caldera_ip,
        config: Config,
        topology="dumbbell",
        number_of_hosts=30,
    ):
        super().__init__(ansible_runner, openstack_conn, caldera_ip, config)
        self.topology = topology
        self.flags = {}
        self.root_flags = {}
        self.number_of_hosts = number_of_hosts
        self.c2c_port = config.c2c_port

    def parse_network(self):
        self.webservers = get_hosts_on_subnet(
            self.openstack_conn, "192.168.200.0/24", host_name_prefix="webserver"
        )
        for host in self.webservers:
            host.users.append("tomcat")

        self.attacker_host = get_hosts_on_subnet(
            self.openstack_conn, "192.168.202.0/24", host_name_prefix="attacker"
        )[0]

        self.database_hosts = get_hosts_on_subnet(
            self.openstack_conn, "192.168.201.0/24", host_name_prefix="database"
        )
        for host in self.database_hosts:
            username = host.name.replace("_", "")
            host.users.append(username)

        webserverSubnet = Subnet("webserver_network", self.webservers, "webserver")
        corportateSubnet = Subnet(
            "critical_company_network",
            self.database_hosts,
            "critical_company",
        )

        self.network = Network("equifax_network", [webserverSubnet, corportateSubnet])

        if len(self.network.get_all_hosts()) != self.number_of_hosts:
            raise Exception(
                f"Number of hosts in network does not match expected number of hosts. Expected {self.number_of_hosts} but got {len(self.network.get_all_hosts())}"
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
                type_name="webserver",
                base_image_name=base_image,
                bake_playbooks=["ansible/bake_playbooks/webserver.yml"],
                baked_image_name="mhbench_webserver_baked",
                bake_extra_vars=defender_vars,
                flavor_name=flavors.small,
                setup_playbook_factories=[
                    lambda host: StartServices(host.ip),
                ],
            ),
            VmBakeSpec(
                type_name="database",
                base_image_name=base_image,
                bake_playbooks=["ansible/bake_playbooks/database.yml"],
                baked_image_name="mhbench_database_baked",
                bake_extra_vars=defender_vars,
                flavor_name=flavors.tiny,
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
        log_event("Deployment Instace", "Setting up Equifax Instance")
        self.find_management_server()
        self.parse_network()

        # Setup apache struts and vulnerability
        webserver_ips = [host.ip for host in self.webservers]
        self.ansible_runner.run_playbook(SetupStrutsVulnerability(webserver_ips))

        # Setup users on corporte hosts
        for host in self.network.get_all_hosts():
            for user in host.users:
                self.ansible_runner.run_playbook(CreateUser(host.ip, user, "ubuntu"))

        for host in self.webservers:
            self.ansible_runner.run_playbook(CreateSSHKey(host.ip, host.users[0]))

        for i, webserver in enumerate(self.webservers):
            database = self.database_hosts[i]
            self.ansible_runner.run_playbook(
                SetupServerSSHKeys(
                    webserver.ip, webserver.users[0], database.ip, database.users[0]
                )
            )

        # Add data to database hosts
        for database in self.database_hosts:
            self.ansible_runner.run_playbook(
                AddData(database.ip, database.users[0], f"~/data_{database.name}.json")
            )
