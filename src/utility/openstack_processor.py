import openstack.connection
import ipaddress

from src.legacy_models import Host


def addr_in_subnet(subnet, addr):
    return ipaddress.ip_address(addr) in ipaddress.ip_network(subnet)


def get_hosts_on_subnet(
    conn: openstack.connection.Connection, subnet, host_name_prefix=""
):
    hosts = []

    # Nova ignores project_id filters for admin tokens, so filter client-side
    # by the project name prefix embedded in every server's name (e.g. "perry_slot0-").
    project_name = conn.auth.get("project_name", "") if conn.auth else ""
    project_prefix = f"{project_name}-" if project_name else ""

    for server in conn.compute.servers():  # type: ignore
        if project_prefix and not server.name.startswith(project_prefix):
            continue
        if host_name_prefix and host_name_prefix not in server.name:
            continue

        for network, network_attrs in server.addresses.items():
            ip_addresses = [x["addr"] for x in network_attrs]
            for ip in ip_addresses:
                if addr_in_subnet(subnet, ip):
                    host = Host(server.name, ip)
                    hosts.append(host)

    return hosts
