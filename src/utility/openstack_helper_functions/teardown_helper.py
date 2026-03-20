import openstack
from openstack.exceptions import SDKException


# Deleting instances
def delete_instances(conn):
    project_id = conn.current_project_id
    servers = [s for s in conn.list_servers() if s.project_id == project_id]
    for server in servers:
        current_sgs = server.security_groups

        if current_sgs:
            # Remove each security group from the server
            for sg in current_sgs:
                # Debug the structure of each security group object
                sg_name = sg.get("id")
                if sg_name:
                    conn.remove_server_security_groups(server, sg_name)

        conn.delete_server(server.id)


# Deleting floating ips
def delete_floating_ips(conn):
    floating_ips = conn.list_floating_ips(filters={"project_id": conn.current_project_id})
    for floating_ip in floating_ips:
        try:
            conn.delete_floating_ip(floating_ip.id)
        except SDKException:
            print(f"  Warning: could not delete floating IP {floating_ip.id}")


# Delete routers
def delete_routers(conn):
    for router in conn.list_routers(filters={"project_id": conn.current_project_id}):
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
def delete_ports(conn):
    networks = conn.list_networks(filters={"project_id": conn.current_project_id})
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


def delete_subnets(conn):
    subnets = conn.list_subnets(filters={"project_id": conn.current_project_id})
    for subnet in subnets:
        if subnet.name in subnet_exclude_list:
            continue
        try:
            conn.delete_subnet(subnet.id)
        except SDKException as e:
            print(f"  Warning: could not delete subnet {subnet.name} ({subnet.id}): {e}")


network_exclude_list = ["shared", "external", "public"]


def delete_networks(conn):
    networks = conn.list_networks(filters={"project_id": conn.current_project_id})
    for network in networks:
        if network.name in network_exclude_list:
            continue
        try:
            conn.delete_network(network.id)
        except SDKException as e:
            print(f"  Warning: could not delete network {network.name} ({network.id}): {e}")


security_group_exclude_list = ["default"]


def delete_security_groups(conn):
    security_groups = conn.list_security_groups(filters={"project_id": conn.current_project_id})
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
