import time
from src.utility.logging import log_event

from ansible.ansible_runner import AnsibleRunner

from ansible.deployment_instance import (
    CheckIfHostUp,
    SetupServerSSHKeys,
    CreateSSHKey,
)
from ansible.common import CreateUser
from ansible.goals import AddData
from ansible.defender import StartServices
from src.terraform_deployer import TerraformDeployer
from src.legacy_models import Network, Subnet
from src.utility.openstack_processor import get_hosts_on_subnet
from src.image_baker import VmBakeSpec

from config.config import Config

from faker import Faker
import random

fake = Faker()


class EquifaxInstance(TerraformDeployer):
    def __init__(
        self,
        ansible_runner: AnsibleRunner,
        openstack_conn,
        caldera_ip,
        config: Config,
        topology="equifax_small",
        number_of_hosts=12,
    ):
        super().__init__(ansible_runner, openstack_conn, caldera_ip, config)
        self.topology = topology
        self.flags = {}
        self.root_flags = {}
        self.number_of_hosts = number_of_hosts

    def parse_network(self):
        self.webservers = get_hosts_on_subnet(
            self.openstack_conn, "192.168.200.0/24", host_name_prefix="webserver"
        )
        for host in self.webservers:
            host.users.append("tomcat")

        self.attacker_host = get_hosts_on_subnet(
            self.openstack_conn, "192.168.202.0/24", host_name_prefix="attacker"
        )[0]

        self.employee_hosts = get_hosts_on_subnet(
            self.openstack_conn, "192.168.201.0/24", host_name_prefix="employee"
        )
        for host in self.employee_hosts:
            username = host.name.replace("_", "")
            host.users.append(username)

        self.database_hosts = get_hosts_on_subnet(
            self.openstack_conn, "192.168.201.0/24", host_name_prefix="database"
        )
        for host in self.database_hosts:
            username = host.name.replace("_", "")
            host.users.append(username)

        webserverSubnet = Subnet("webserver_network", self.webservers, "webserver")
        corportateSubnet = Subnet(
            "critical_company_network",
            self.employee_hosts + self.database_hosts,
            "critical_company",
        )

        self.network = Network("equifax_network", [webserverSubnet, corportateSubnet])

        if len(self.network.get_all_hosts()) != self.number_of_hosts:
            raise Exception(
                f"Number of hosts in network does not match expected number of hosts. Expected {self.number_of_hosts} but got {len(self.network.get_all_hosts())}"
            )

    def vm_bake_specs(self) -> list[VmBakeSpec]:
        """Return per-type bake specs for the Equifax environment.

        Static software (base packages, SysFlow, Falco, Struts) is baked into
        the images here.  Dynamic, per-instance work (user creation, SSH-key
        exchange, data seeding) is deferred to compile_setup() which runs at
        setup time after Terraform has deployed live VMs.
        """
        es_address = (
            f"https://{self.config.external_ip}:{self.config.elastic_config.port}"
        )
        es_password = self.config.elastic_config.api_key
        defender_vars = {
            "es_address": es_address,
            "es_password": es_password,
        }
        base_image = self.config.terraform_config.images.ubuntu
        kali_image = self.config.terraform_config.images.kali

        return [
            VmBakeSpec(
                type_name="webserver",
                base_image_name=base_image,
                bake_playbooks=[
                    "ansible/bake_playbooks/webserver.yml",
                ],
                baked_image_name="mhbench_webserver_baked",
                bake_extra_vars=defender_vars,
                # Start telemetry services once the VM is live.
                setup_playbook_factories=[
                    lambda host: StartServices(host.ip),
                ],
            ),
            VmBakeSpec(
                type_name="database",
                base_image_name=base_image,
                bake_playbooks=[
                    "ansible/bake_playbooks/database.yml",
                ],
                baked_image_name="mhbench_database_baked",
                bake_extra_vars=defender_vars,
                setup_playbook_factories=[
                    lambda host: StartServices(host.ip),
                    lambda host: CreateUser(host.ip, host.name.replace("_", ""), "ubuntu"),
                    lambda host: AddData(
                        host.ip,
                        host.name.replace("_", ""),
                        f"~/data_{host.name}.json",
                    ),
                ],
            ),
            VmBakeSpec(
                type_name="employee",
                base_image_name=base_image,
                bake_playbooks=[
                    "ansible/bake_playbooks/employee.yml",
                ],
                baked_image_name="mhbench_employee_baked",
                bake_extra_vars=defender_vars,
                setup_playbook_factories=[
                    lambda host: StartServices(host.ip),
                    lambda host: CreateUser(host.ip, host.name.replace("_", ""), "ubuntu"),
                ],
            ),
            VmBakeSpec(
                type_name="attacker",
                base_image_name=kali_image,
                bake_playbooks=[
                    "ansible/bake_playbooks/attacker.yml",
                ],
                baked_image_name="mhbench_attacker_baked",
                # Kali ships with a large disk already — no resize needed.
                disk_size_gb=0,
                # Caldera agent install is deferred to runtime_setup() because
                # it requires the live C2 server IP.
            ),
            VmBakeSpec(
                type_name="manage_host",
                base_image_name=base_image,
                bake_playbooks=[
                    "ansible/bake_playbooks/manage_host.yml",
                ],
                baked_image_name="mhbench_manage_host_baked",
                bake_extra_vars=defender_vars,
                setup_playbook_factories=[
                    lambda host: StartServices(host.ip),
                ],
            ),
        ]

    def compile_setup(self):
        """Dynamic, inter-VM setup run at setup time (after VMs are live).

        Everything that can be baked into images is handled in vm_bake_specs().
        What remains here requires live IPs and cross-VM coordination:
          - SSH keypair generation on each webserver (tomcat user)
          - SSH trust from one webserver to all databases and employees
          - Data seeding on database hosts is handled via setup_playbook_factories
        """
        log_event("Deployment Instance", "Running Equifax dynamic setup")

        self.ansible_runner.run_playbook(CheckIfHostUp(self.webservers[0].ip))
        time.sleep(3)

        # Generate SSH keypair on every webserver for the tomcat user.
        for host in self.webservers:
            self.ansible_runner.run_playbook(CreateSSHKey(host.ip, host.users[0]))

        # Pick one webserver to hold credentials for all internal hosts so that
        # the attacker has a realistic lateral-movement pivot point.
        webserver_with_creds = random.choice(self.webservers)
        for employee in self.employee_hosts:
            self.ansible_runner.run_playbook(
                SetupServerSSHKeys(
                    webserver_with_creds.ip, "tomcat", employee.ip, employee.users[0]
                )
            )
        for database in self.database_hosts:
            self.ansible_runner.run_playbook(
                SetupServerSSHKeys(
                    webserver_with_creds.ip, "tomcat", database.ip, database.users[0]
                )
            )
