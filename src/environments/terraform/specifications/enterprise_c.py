from src.environments.terraform.specifications.ics import ICSEnvironment


class EnterpriseC(ICSEnvironment):
    def __init__(self, ansible_runner, openstack_conn, caldera_ip, config):
        super().__init__(
            ansible_runner, openstack_conn, caldera_ip, config, topology="enterprise_c"
        )
