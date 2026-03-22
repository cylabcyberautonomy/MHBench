import time
from src.utility.logging import log_event

from ansible.ansible_runner import AnsibleRunner

from ansible.deployment_instance import (
    CheckIfHostUp,
    SetupServerSSHKeys,
)
from ansible.common import CreateUser
from ansible.vulnerabilities import SetupNetcatShell
from ansible.caldera import InstallAttacker
from ansible.defender import StartServices

from src.terraform_deployer import TerraformDeployer
from src.image_baker import VmBakeSpec
from src.legacy_models import Network, Subnet
from src.utility.openstack_processor import get_hosts_on_subnet

from config.config import Config

from faker import Faker
import random

fake = Faker()

NUMBER_ICS_HOSTS = 47


class ICSEnvironment(TerraformDeployer):
    def __init__(
        self,
        ansible_runner: AnsibleRunner,
        openstack_conn,
        caldera_ip,
        config: Config,
        topology="ics_inspired",
    ):
        super().__init__(ansible_runner, openstack_conn, caldera_ip, config)
        self.topology = topology
        self.flags = {}
        self.root_flags = {}

    def parse_network(self):
        self.employee_one_hosts = get_hosts_on_subnet(
            self.openstack_conn, "192.168.200.0/24", host_name_prefix="employee_A"
        )

        self.manage_one_host = get_hosts_on_subnet(
            self.openstack_conn, "192.168.200.0/24", host_name_prefix="manage"
        )

        self.all_employee_one_hosts = self.employee_one_hosts + self.manage_one_host

        self.manage_two_host = get_hosts_on_subnet(
            self.openstack_conn, "192.168.201.0/24", host_name_prefix="manage"
        )

        self.employee_two_hosts = get_hosts_on_subnet(
            self.openstack_conn, "192.168.201.0/24", host_name_prefix="employee_B"
        )
        self.all_employee_two_hosts = self.employee_two_hosts + self.manage_two_host

        self.manage_hosts = self.manage_one_host + self.manage_two_host

        self.attacker_host = get_hosts_on_subnet(
            self.openstack_conn, "192.168.202.0/24", host_name_prefix="attacker"
        )[0]

        self.ot_sensors = get_hosts_on_subnet(
            self.openstack_conn, "192.168.203.0/24", host_name_prefix="sensor"
        )

        self.ot_hosts = get_hosts_on_subnet(
            self.openstack_conn, "192.168.203.0/24", host_name_prefix="control_host"
        )

        employeeOneSubnet = Subnet(
            "employee_one_network", self.all_employee_one_hosts, "employee_one_group"
        )
        employeeTwoSubnet = Subnet(
            "employee_two_network", self.all_employee_two_hosts, "employee_two_group"
        )
        otSubnet = Subnet("OT_network", self.ot_sensors + self.ot_hosts, "ot_group")

        self.network = Network(
            "ics_inspired", [employeeOneSubnet, employeeTwoSubnet, otSubnet]
        )
        for host in self.network.get_all_hosts():
            username = host.name.replace("_", "")
            host.users.append(username)

        if len(self.network.get_all_hosts()) != NUMBER_ICS_HOSTS:
            raise Exception(
                f"Number of hosts in network does not match expected number of hosts. Expected {NUMBER_ICS_HOSTS} but got {len(self.network.get_all_hosts())}"
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
                type_name="employee_A",
                base_image_name=base_image,
                bake_playbooks=["ansible/bake_playbooks/employee.yml"],
                baked_image_name="mhbench_employee_baked",
                bake_extra_vars=defender_vars,
                flavor_name=flavors.small,
                setup_playbook_factories=[lambda host: StartServices(host.ip)],
            ),
            VmBakeSpec(
                type_name="manage",
                base_image_name=base_image,
                bake_playbooks=["ansible/bake_playbooks/manage_host.yml"],
                baked_image_name="mhbench_manage_host_baked",
                bake_extra_vars=defender_vars,
                flavor_name=flavors.small,
                setup_playbook_factories=[lambda host: StartServices(host.ip)],
            ),
            VmBakeSpec(
                type_name="employee_B",
                base_image_name=base_image,
                bake_playbooks=["ansible/bake_playbooks/employee.yml"],
                baked_image_name="mhbench_employee_baked",
                bake_extra_vars=defender_vars,
                flavor_name=flavors.small,
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
            VmBakeSpec(
                type_name="sensor",
                base_image_name=base_image,
                bake_playbooks=["ansible/bake_playbooks/employee.yml"],
                baked_image_name="mhbench_employee_baked",
                bake_extra_vars=defender_vars,
                flavor_name=flavors.small,
                setup_playbook_factories=[lambda host: StartServices(host.ip)],
            ),
            VmBakeSpec(
                type_name="control_host",
                base_image_name=base_image,
                bake_playbooks=["ansible/bake_playbooks/employee.yml"],
                baked_image_name="mhbench_employee_baked",
                bake_extra_vars=defender_vars,
                flavor_name=flavors.small,
                setup_playbook_factories=[lambda host: StartServices(host.ip)],
            ),
        ]

    def compile_setup(self):
        log_event("Deployment Instance", "Setting up ICS network")

        self.ansible_runner.run_playbook(CheckIfHostUp(self.employee_one_hosts[0].ip))
        time.sleep(3)

        # Setup users on all hosts
        for host in self.network.get_all_hosts():
            for user in host.users:
                self.ansible_runner.run_playbook(CreateUser(host.ip, user, "ubuntu"))

        # Random employee on subnet one
        for manage_host in self.manage_hosts:
            # Setup netcat shell on vulnerable employee
            self.ansible_runner.run_playbook(
                SetupNetcatShell(manage_host.ip, manage_host.users[0])
            )

            # Each employee has SSH keys to all ot sensors
            for sensor in self.ot_sensors:
                self.ansible_runner.run_playbook(
                    SetupServerSSHKeys(
                        manage_host.ip,
                        manage_host.users[0],
                        sensor.ip,
                        sensor.users[0],
                    )
                )

        # Randomly choose 5 OT sensors to have ssh keys to ot hosts
        critical_sensors = random.sample(self.ot_sensors, 5)
        for i, ot_host in enumerate(self.ot_hosts):
            sensor = critical_sensors[i]
            self.ansible_runner.run_playbook(
                SetupServerSSHKeys(
                    sensor.ip,
                    sensor.users[0],
                    ot_host.ip,
                    ot_host.users[0],
                )
            )

    def runtime_setup(self):
        # Randomly choose 1 employee to have attacker
        employee_hosts = self.employee_one_hosts + self.employee_two_hosts
        employee_host = random.choice(employee_hosts)

        # Setup attacker
        self.ansible_runner.run_playbook(
            InstallAttacker(employee_host.ip, employee_host.users[0], self.caldera_ip)
        )
