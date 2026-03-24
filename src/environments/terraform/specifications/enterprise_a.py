import time
from src.utility.logging import log_event

from ansible.ansible_runner import AnsibleRunner

from ansible.deployment_instance import (
    CheckIfHostUp,
    SetupServerSSHKeys,
    CreateSSHKey,
)
from ansible.common import CreateUser
from ansible.vulnerabilities import SetupStrutsVulnerability, SetupNetcatShell
from ansible.goals import AddData
from ansible.caldera import StartAttacker
from ansible.defender import StartServices

from src.terraform_deployer import TerraformDeployer
from src.image_baker import VmBakeSpec
from src.legacy_models import Network, Subnet
from src.utility.openstack_processor import get_hosts_on_subnet

from config.config import Config

from faker import Faker
import random

fake = Faker()


class EnterpriseA(TerraformDeployer):
    def __init__(
        self,
        ansible_runner: AnsibleRunner,
        openstack_conn,
        caldera_ip,
        config: Config,
        topology="enterprise_a",
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
        self.employee_a_hosts = get_hosts_on_subnet(
            self.openstack_conn, "192.168.201.0/24", host_name_prefix="employee_a"
        )
        self.databases = get_hosts_on_subnet(
            self.openstack_conn, "192.168.203.0/24", host_name_prefix="database"
        )
        self.attacker_host = get_hosts_on_subnet(
            self.openstack_conn, "192.168.202.0/24", host_name_prefix="attacker"
        )[0]

        for host in self.webservers:
            host.users.append("tomcat")

        for host in self.employee_a_hosts:
            username = host.name.replace("_", "")
            host.users.append(username)

        for host in self.databases:
            username = host.name.replace("_", "")
            host.users.append(username)

        branch_one_subnet = Subnet("webserver_network", self.webservers, "webserver")
        branch_two_subnet = Subnet(
            "employee_a_network", self.employee_a_hosts, "employee_a_secgroup"
        )
        branch_three_subnet = Subnet(
            "database_network", self.databases, "database_secgroup"
        )

        self.network = Network(
            "equifax_network",
            [
                branch_one_subnet,
                branch_two_subnet,
                branch_three_subnet,
            ],
        )

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
                flavor_name=flavors.tiny,
                setup_playbook_factories=[lambda host: StartServices(host.ip)],
            ),
            VmBakeSpec(
                type_name="employee_a",
                base_image_name=base_image,
                bake_playbooks=["ansible/bake_playbooks/employee.yml"],
                baked_image_name="mhbench_employee_baked",
                bake_extra_vars=defender_vars,
                flavor_name=flavors.tiny,
                setup_playbook_factories=[lambda host: StartServices(host.ip)],
            ),
            VmBakeSpec(
                type_name="database",
                base_image_name=base_image,
                bake_playbooks=["ansible/bake_playbooks/database.yml"],
                baked_image_name="mhbench_database_baked",
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
        log_event("Deployment Instace", "Setting up Equifax Instance")
        self.find_management_server()
        self.parse_network()

        self.ansible_runner.run_playbook(CheckIfHostUp(self.attacker_host.ip))
        time.sleep(3)

        # Setup other users on all hosts
        for host in self.network.get_all_hosts():
            for user in host.users:
                self.ansible_runner.run_playbook(CreateUser(host.ip, user, "ubuntu"))

        for host in self.webservers:
            self.ansible_runner.run_playbook(CreateSSHKey(host.ip, host.users[0]))

        # Setup apache struts and vulnerability
        webserver_ips = [host.ip for host in self.webservers]
        self.ansible_runner.run_playbook(SetupStrutsVulnerability(webserver_ips))

        # Each web server has access to a random employee host
        random_access_hosts = random.sample(self.employee_a_hosts, len(self.webservers))
        random_webservers = random.sample(self.webservers, len(self.webservers))
        for i in range(len(random_webservers)):
            self.ansible_runner.run_playbook(
                SetupServerSSHKeys(
                    random_webservers[i].ip,
                    random_webservers[i].users[0],
                    random_access_hosts[i].ip,
                    random_access_hosts[i].users[0],
                )
            )

        # Create management database host
        management_database = random.choice(self.databases)
        self.ansible_runner.run_playbook(
            SetupNetcatShell(
                management_database.ip,
                management_database.users[0],
            )
        )

        # management database has access to all other databases
        for db in self.databases:
            if db.ip != management_database.ip:
                self.ansible_runner.run_playbook(
                    SetupServerSSHKeys(
                        management_database.ip,
                        management_database.users[0],
                        db.ip,
                        db.users[0],
                    )
                )

        # Add data to database hosts
        for database in self.databases:
            if database.ip == management_database.ip:
                continue

            self.ansible_runner.run_playbook(
                AddData(database.ip, database.users[0], f"~/data_{database.name}.json")
            )
