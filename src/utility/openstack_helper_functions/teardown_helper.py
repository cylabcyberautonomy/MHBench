import openstack
from openstack.exceptions import SDKException


# Collect floating IP IDs associated with prefix-matched servers (call before deleting instances)
def collect_floating_ips(conn, name_prefix: str = "") -> list[str]:
    servers = [s for s in conn.list_servers() if s.name.startswith(name_prefix)]
    floating_addrs = set()
    for server in servers:
        for network_attrs in server.addresses.values():
            for addr_info in network_attrs:
                if addr_info.get("OS-EXT-IPS:type") == "floating":
                    floating_addrs.add(addr_info["addr"])
    if not floating_addrs:
        return []
    return [
        fip.id
        for fip in conn.list_floating_ips(filters={"project_id": conn.current_project_id})
        if fip.floating_ip_address in floating_addrs
    ]


# Deleting instances
def delete_instances(conn, name_prefix: str = ""):
    servers = [
        s for s in conn.list_servers()
        if s.name.startswith(name_prefix)
    ]
    for server in servers:
        current_sgs = server.security_groups

        if current_sgs:
            # Remove each security group from the server
            for sg in current_sgs:
                sg_name = sg.get("id")
                if sg_name:
                    conn.remove_server_security_groups(server, sg_name)

        conn.delete_server(server.id)


# Deleting floating ips
# If fip_ids is provided, delete only those; otherwise delete all in the project (cleaner use-case).
def delete_floating_ips(conn, fip_ids: list[str] | None = None):
    if fip_ids is not None:
        ids_to_delete = fip_ids
    else:
        ids_to_delete = [
            f.id for f in conn.list_floating_ips(filters={"project_id": conn.current_project_id})
        ]
    for fip_id in ids_to_delete:
        try:
            conn.delete_floating_ip(fip_id)
        except SDKException:
            print(f"  Warning: could not delete floating IP {fip_id}")


# Delete routers
def delete_routers(conn, name_prefix: str = ""):
    routers = conn.list_routers(filters={"project_id": conn.current_project_id})
    if name_prefix:
        routers = [r for r in routers if r.name.startswith(name_prefix)]
    for router in routers:
        # First, detach all router interfaces
        for port in conn.network.ports(device_id=router.id):
            if port.device_owner == "network:router_interface" and port.fixed_ips:
                subnet_id = port.fixed_ips[0]["subnet_id"]
                try:
                    conn.remove_router_interface(router, subnet_id=subnet_id)
                except SDKException:
                    print(
                        f"Error removing router interface {subnet_id} from router {router.id}"
                    )
                    continue

        try:
            conn.delete_router(router.id)
        except SDKException as e:
            print(f"  Warning: could not delete router {router.id}: {e}")


# Delete all ports
def delete_ports(conn, name_prefix: str = ""):
    networks = conn.list_networks(filters={"project_id": conn.current_project_id})
    if name_prefix:
        networks = [n for n in networks if n.name.startswith(name_prefix)]
    for network in networks:
        # Disable DHCP on every subnet in this network so the Neutron DHCP
        # agent releases its port, unblocking subnet deletion.
        for subnet_id in network.get("subnets", []):
            try:
                conn.update_subnet(subnet_id, enable_dhcp=False)
            except SDKException:
                pass

        # Filter by network_id to catch any remaining ports (DHCP or otherwise).
        ports = conn.list_ports(filters={"network_id": network.id})
        for port in ports:
            try:
                conn.update_port(port.id, fixed_ips=[])
            except SDKException:
                pass
            try:
                conn.delete_port(port.id)
            except SDKException:
                pass


subnet_exclude_list = [
    "shared-subnet",
    "external",
    "ext-subnet",
    "public-subnet",
    "ipv6-public-subnet",
]


def delete_subnets(conn, name_prefix: str = ""):
    subnets = conn.list_subnets(filters={"project_id": conn.current_project_id})
    if name_prefix:
        subnets = [s for s in subnets if s.name.startswith(name_prefix)]
    for subnet in subnets:
        if subnet.name in subnet_exclude_list:
            continue
        try:
            conn.delete_subnet(subnet.id)
        except SDKException as e:
            print(f"  Warning: could not delete subnet {subnet.name} ({subnet.id}): {e}")


network_exclude_list = ["shared", "external", "public"]


def delete_networks(conn, name_prefix: str = ""):
    networks = conn.list_networks(filters={"project_id": conn.current_project_id})
    if name_prefix:
        networks = [n for n in networks if n.name.startswith(name_prefix)]
    for network in networks:
        if network.name in network_exclude_list:
            continue
        try:
            conn.delete_network(network.id)
        except SDKException as e:
            print(f"  Warning: could not delete network {network.name} ({network.id}): {e}")


security_group_exclude_list = ["default"]


def delete_security_groups(conn, name_prefix: str = ""):
    security_groups = conn.list_security_groups(filters={"project_id": conn.current_project_id})
    if name_prefix:
        security_groups = [sg for sg in security_groups if sg.name.startswith(name_prefix)]
    to_delete = [sg for sg in security_groups if sg.name not in security_group_exclude_list]
    for sg in to_delete:
        # Remove this SG from any ports still referencing it (e.g. DHCP ports
        # that survived network/subnet deletion), otherwise Neutron will reject
        # the delete with "Security Group X in use".
        for port in conn.network.ports(project_id=conn.current_project_id):
            if sg.id in (port.security_group_ids or []):
                try:
                    updated = [s for s in port.security_group_ids if s != sg.id]
                    conn.network.update_port(port.id, security_groups=updated)
                except SDKException as e:
                    print(f"  Warning: could not remove SG {sg.name} from port {port.id}: {e}")
        try:
            conn.delete_security_group(sg.id)
        except SDKException as e:
            print(f"  Warning: could not delete security group {sg.name} ({sg.id}): {e}")
