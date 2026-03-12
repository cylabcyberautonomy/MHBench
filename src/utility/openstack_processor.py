import openstack.connection
import ipaddress

from src.legacy_models import Host


def addr_in_subnet(subnet, addr):
    return ipaddress.ip_address(addr) in ipaddress.ip_network(subnet)


def get_hosts_on_subnet(
    conn: openstack.connection.Connection, subnet, host_name_prefix=""
):
    hosts = []

    for server in conn.compute.servers():  # type: ignore
        if host_name_prefix and host_name_prefix not in server.name:
            continue

        for network, network_attrs in server.addresses.items():
            ip_addresses = [x["addr"] for x in network_attrs]
            for ip in ip_addresses:
                if addr_in_subnet(subnet, ip):
                    host = Host(server.name, ip)
                    hosts.append(host)

    return hosts
