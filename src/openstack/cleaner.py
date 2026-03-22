from openstack.connection import Connection
from src.utility.openstack_helper_functions import teardown_helper
import time


class OpenstackCleaner:
    def __init__(self, openstack_conn: Connection):
        self.openstack_conn = openstack_conn

    def clean_environment(self):
        print("Tearing down...")

        conn = self.openstack_conn

        teardown_helper.delete_instances(conn)
        while conn.list_servers(filters={"project_id": conn.current_project_id}):
            time.sleep(0.5)

        teardown_helper.delete_floating_ips(conn)
        while conn.list_floating_ips(filters={"project_id": conn.current_project_id}):
            time.sleep(0.5)

        teardown_helper.delete_routers(conn)
        while conn.list_routers(filters={"project_id": conn.current_project_id}):
            time.sleep(0.5)

        teardown_helper.delete_ports(conn)
        teardown_helper.delete_subnets(conn)
        teardown_helper.delete_networks(conn)
        teardown_helper.delete_security_groups(conn)
