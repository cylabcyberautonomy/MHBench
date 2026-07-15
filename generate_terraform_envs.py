"""Generate v3_MHBench environment JSONs from MHBench terraform specifications.

Each class of environment is encoded directly. Where the Python spec used randomization
(random.choice, random.sample) we pick deterministic values: always index-0 or the first N.

Output: environments/terraform/*.json
"""

import json
from itertools import combinations
from pathlib import Path

DST_DIR = Path(__file__).parent / "environments"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def host(name: str, vm_type: str, ip: str, flavor: str = "m1.small") -> dict:
    h = {"name": name, "vm_type": vm_type, "flavor": flavor, "ip_address": ip}
    return h


def host_no_ip(name: str, vm_type: str, flavor: str = "m1.small") -> dict:
    return {"name": name, "vm_type": vm_type, "flavor": flavor}


def subnet(name: str, cidr: str, hosts: list, dns=None, external=False) -> dict:
    s = {
        "name": name,
        "cidr": cidr,
        "dns_servers": dns or ["8.8.8.8"],
        "hosts": hosts,
    }
    if external:
        s["external"] = True
    return s


def conn(a: str, b: str) -> dict:
    return {"from_subnet": a, "to_subnet": b, "protocol": None, "ports": None, "bidirectional": True}


def all_pairs_connections(subnet_names: list) -> list:
    return [conn(a, b) for a, b in combinations(subnet_names, 2)]


def playbook(name: str, **args) -> dict:
    return {"name": name, "args": args}


def add_data(host_name: str, user: str, path: str = None) -> dict:
    return playbook("add_data", host=host_name, host_user=user,
                    path=path or f"~/data_{host_name}.json")


def setup_ssh_keys(from_host: str, from_user: str, to_host: str, to_user: str) -> dict:
    return playbook("setup_ssh_keys",
                    host=from_host, host_user=from_user,
                    follower=to_host, follower_user=to_user)


def topology(name: str, description: str, subnets: list, connections: list,
             playbooks: list) -> dict:
    return {
        "name": name,
        "networks": [{"name": name + "_network", "description": description, "subnets": subnets}],
        "subnet_connections": connections,
        "playbooks": playbooks,
    }


# Shared attacker subnet (all terraform envs use the same attacker module)
ATTACKER_SUBNET = subnet(
    "attacker_subnet", "192.168.202.0/24",
    [host("attacker", "kali_running", "192.168.202.100", flavor="m2.large")],
)

# ---------------------------------------------------------------------------
# Equifax family: webservers (setup_struts baked) + databases + attacker
# One webserver (index 0) sets up SSH keys to all databases.
# ---------------------------------------------------------------------------

def equifax_topology(topo_name: str, desc: str, n_webservers: int, n_databases: int) -> dict:
    webservers = [
        host(f"webserver_{i}", "webserver_running", f"192.168.200.{10 + i}")
        for i in range(n_webservers)
    ]
    databases = [
        host(f"database_{i}", "ubuntu_base_running", f"192.168.201.{50 + i}")
        for i in range(n_databases)
    ]

    subnets = [
        subnet("webserver_subnet", "192.168.200.0/24", webservers),
        subnet("corporate_subnet", "192.168.201.0/24", databases),
        ATTACKER_SUBNET,
    ]
    conns = all_pairs_connections(["webserver_subnet", "corporate_subnet", "attacker_subnet"])

    pbs = []
    # webserver_0 (tomcat user) → each database
    pbs.append(playbook("equifax_ssh_config", host="webserver_0", host_user="tomcat"))
    for i in range(n_databases):
        pbs.append(setup_ssh_keys("webserver_0", "tomcat", f"database_{i}", "ubuntu"))
    for i in range(n_databases):
        pbs.append(add_data(f"database_{i}", "ubuntu"))

    return topology(topo_name, desc, subnets, conns, pbs)


EQUIFAX_SMALL = equifax_topology(
    "equifax_small", "Equifax-inspired: 2 webservers, 4 databases", 2, 4)

EQUIFAX_MEDIUM = equifax_topology(
    "equifax_medium", "Equifax-inspired: 2 webservers, 24 databases", 2, 24)

EQUIFAX_LARGE = equifax_topology(
    "equifax_large", "Equifax-inspired: 2 webservers, 48 databases", 2, 48)


# ---------------------------------------------------------------------------
# Dumbbell: 15 webservers + 15 databases, webserver_i <-> database_i SSH keys
# ---------------------------------------------------------------------------

def dumbbell_topology(with_pe: bool) -> dict:
    n = 15

    def webserver_vm_type(i):
        if not with_pe:
            return "webserver_running"
        # even → setup_struts + writeable, odd → setup_struts + sudobaron
        return "webserver_writeable_running" if i % 2 == 0 else "webserver_sudobaron_running"

    webservers = [
        host(f"webserver_{i}", webserver_vm_type(i), f"192.168.200.{10 + i}")
        for i in range(n)
    ]
    databases = [
        host(f"database_{i}", "ubuntu_base_running", f"192.168.201.{50 + i}")
        for i in range(n)
    ]

    subnets = [
        subnet("webserver_subnet", "192.168.200.0/24", webservers),
        subnet("corporate_subnet", "192.168.201.0/24", databases),
        ATTACKER_SUBNET,
    ]
    conns = all_pairs_connections(["webserver_subnet", "corporate_subnet", "attacker_subnet"])

    pbs = []
    # dumbbell.py uses webserver.users[0] = "tomcat"; dumbbell_pe.py uses "root"
    from_user = "root" if with_pe else "tomcat"
    if not with_pe:
        for i in range(n):
            pbs.append(playbook("equifax_ssh_config", host=f"webserver_{i}", host_user="tomcat"))
    for i in range(n):
        pbs.append(setup_ssh_keys(f"webserver_{i}", from_user, f"database_{i}", "ubuntu"))
    for i in range(n):
        pbs.append(add_data(f"database_{i}", "ubuntu"))

    name = "dumbbell_pe" if with_pe else "dumbbell"
    desc = ("Dumbbell with webservers (struts+privesc alternating) and databases"
            if with_pe else
            "Dumbbell: 15 webservers (struts) and 15 databases")
    return topology(name, desc, subnets, conns, pbs)


DUMBBELL = dumbbell_topology(with_pe=False)
DUMBBELL_PE = dumbbell_topology(with_pe=True)


# ---------------------------------------------------------------------------
# Chain / Ring: N hosts in a linear SSH-key chain, attacker → host_0
# ---------------------------------------------------------------------------

def chain_topology(name: str, n_hosts: int, with_pe: bool) -> dict:
    def host_vm_type(i):
        if not with_pe:
            return "ubuntu_base_running"
        # even → writeable, odd → sudobaron
        return "ubuntu_writeable_running" if i % 2 == 0 else "ubuntu_sudobaron_running"

    ring_hosts = [
        host(f"host_{i}", host_vm_type(i), f"192.168.200.{10 + i}")
        for i in range(n_hosts)
    ]

    subnets = [
        subnet("ring_subnet", "192.168.200.0/24", ring_hosts),
        ATTACKER_SUBNET,
    ]
    conns = [conn("ring_subnet", "attacker_subnet")]

    pbs = []
    # Attacker → host_0
    pbs.append(setup_ssh_keys("attacker", "root", "host_0", "ubuntu"))
    # Chain: host_i → host_{i+1}
    for i in range(n_hosts - 1):
        pbs.append(setup_ssh_keys(f"host_{i}", "ubuntu", f"host_{i + 1}", "ubuntu"))
    # add_data: chain_pe uses root; chain uses host's user (ubuntu in v3)
    data_user = "root" if with_pe else "ubuntu"
    for i in range(n_hosts):
        pbs.append(add_data(f"host_{i}", data_user))

    desc = (f"Chain of {n_hosts} hosts with privesc vulnerabilities"
            if with_pe else f"Chain of {n_hosts} hosts")
    return topology(name, desc, subnets, conns, pbs)


CHAIN = chain_topology("chain", 25, with_pe=False)
CHAIN_PE = chain_topology("chain_pe", 25, with_pe=True)
CHAIN_2HOSTS = chain_topology("chain_2hosts", 2, with_pe=False)


# ---------------------------------------------------------------------------
# Star: 25 hosts split into webservers (struts), nc_hosts (netcat), ssh_hosts
# Attacker has SSH keys to all ssh_hosts.
# ---------------------------------------------------------------------------

def star_topology(name: str, with_pe: bool) -> dict:
    n = 25
    n_web = n // 3       # 8
    n_nc = n // 3        # 8
    # n_ssh = n - n_web - n_nc  # 9

    def host_vm_type(i):
        is_web = i < n_web
        is_nc = n_web <= i < n_web + n_nc
        is_ssh = i >= n_web + n_nc

        if with_pe:
            # alternating sudobaron (even) / writeable (odd) across ALL hosts
            pe = "sudobaron" if i % 2 == 0 else "writeable"
            if is_web:
                return f"webserver_sudobaron_running" if pe == "sudobaron" else "webserver_writeable_running"
            if is_nc:
                return f"ubuntu_netcat_sudobaron_running" if pe == "sudobaron" else "ubuntu_netcat_writeable_running"
            # ssh host
            return f"ubuntu_sudobaron_running" if pe == "sudobaron" else "ubuntu_writeable_running"
        else:
            if is_web:
                return "webserver_running"
            if is_nc:
                return "ubuntu_netcat_running"
            return "ubuntu_base_running"

    ring_hosts = [
        host(f"host_{i}", host_vm_type(i), f"192.168.200.{10 + i}")
        for i in range(n)
    ]

    subnets = [
        subnet("ring_subnet", "192.168.200.0/24", ring_hosts),
        ATTACKER_SUBNET,
    ]
    conns = [conn("ring_subnet", "attacker_subnet")]

    pbs = []
    # Attacker has SSH keys to all ssh_hosts (indices n_web+n_nc..n-1)
    for i in range(n_web + n_nc, n):
        pbs.append(setup_ssh_keys("attacker", "root", f"host_{i}", "ubuntu"))
    # add_data on all hosts; star_pe uses root, star uses host's user
    data_user = "root" if with_pe else "ubuntu"
    for i in range(n):
        pbs.append(add_data(f"host_{i}", data_user))

    desc = ("Star topology: webservers (struts), netcat hosts, ssh-key hosts — with privesc"
            if with_pe else
            "Star topology: webservers (struts), netcat hosts, ssh-key hosts")
    return topology(name, desc, subnets, conns, pbs)


STAR = star_topology("star", with_pe=False)
STAR_PE = star_topology("star_pe", with_pe=True)


# ---------------------------------------------------------------------------
# Enterprise A: webservers + employee_a + databases
# webserver_i → employee_a_i (SSH); mgmt_db (database_0) has netcat + SSH to all other dbs
# ---------------------------------------------------------------------------

def enterprise_a_topology() -> dict:
    n_web = 10
    n_emp = 10
    n_db = 10

    webservers = [
        host(f"webserver_{i}", "webserver_running", f"192.168.200.{10 + i}")
        for i in range(n_web)
    ]
    employees = [
        host(f"employee_a_{i}", "ubuntu_base_running", f"192.168.201.{50 + i}")
        for i in range(n_emp)
    ]
    # database_0 is the management db (netcat_shell baked in)
    databases = [
        host("database_0", "ubuntu_netcat_running", "192.168.203.50"),
        *[
            host(f"database_{i}", "ubuntu_base_running", f"192.168.203.{50 + i}")
            for i in range(1, n_db)
        ],
    ]

    subnets = [
        subnet("webserver_subnet", "192.168.200.0/24", webservers),
        subnet("employee_a_subnet", "192.168.201.0/24", employees),
        subnet("database_subnet", "192.168.203.0/24", databases),
        ATTACKER_SUBNET,
    ]
    conns = all_pairs_connections(
        ["webserver_subnet", "employee_a_subnet", "database_subnet", "attacker_subnet"]
    )

    pbs = []
    # webserver setup
    for i in range(n_web):
        pbs.append(playbook("equifax_ssh_config", host=f"webserver_{i}", host_user="tomcat"))
    # webserver_i → employee_a_i
    for i in range(n_web):
        pbs.append(setup_ssh_keys(f"webserver_{i}", "tomcat", f"employee_a_{i}", "ubuntu"))
    # management database_0 → all other databases
    for i in range(1, n_db):
        pbs.append(setup_ssh_keys("database_0", "ubuntu", f"database_{i}", "ubuntu"))
    # add_data on non-management databases
    for i in range(1, n_db):
        pbs.append(add_data(f"database_{i}", "ubuntu"))

    return topology(
        "enterprise_a",
        "Enterprise A: webservers, employee subnet, database subnet with management db",
        subnets, conns, pbs,
    )


ENTERPRISE_A = enterprise_a_topology()


# ---------------------------------------------------------------------------
# Enterprise B: webservers + employee_a + employee_b + databases
# webserver_i → employee_a_i; employee_a_0 (root) → all databases; sudobaron on all employees
# ---------------------------------------------------------------------------

def enterprise_b_topology() -> dict:
    n_web = 10
    n_emp_a = 10
    n_emp_b = 10
    n_db = 10

    webservers = [
        host(f"webserver_{i}", "webserver_running", f"192.168.200.{10 + i}")
        for i in range(n_web)
    ]
    # All employees have sudobaron baked in
    employees_a = [
        host(f"employee_a_{i}", "ubuntu_sudobaron_running", f"192.168.201.{50 + i}")
        for i in range(n_emp_a)
    ]
    employees_b = [
        host(f"employee_b_{i}", "ubuntu_sudobaron_running", f"192.168.204.{50 + i}")
        for i in range(n_emp_b)
    ]
    databases = [
        host(f"database_{i}", "ubuntu_base_running", f"192.168.203.{50 + i}")
        for i in range(n_db)
    ]

    subnets = [
        subnet("webserver_subnet", "192.168.200.0/24", webservers),
        subnet("employee_a_subnet", "192.168.201.0/24", employees_a),
        subnet("employee_b_subnet", "192.168.204.0/24", employees_b),
        subnet("database_subnet", "192.168.203.0/24", databases),
        ATTACKER_SUBNET,
    ]
    conns = all_pairs_connections([
        "webserver_subnet", "employee_a_subnet", "employee_b_subnet",
        "database_subnet", "attacker_subnet",
    ])

    pbs = []
    for i in range(n_web):
        pbs.append(playbook("equifax_ssh_config", host=f"webserver_{i}", host_user="tomcat"))
    # webserver_i → employee_a_i
    for i in range(n_web):
        pbs.append(setup_ssh_keys(f"webserver_{i}", "tomcat", f"employee_a_{i}", "ubuntu"))
    # employee_a_0 (root) → all databases
    for i in range(n_db):
        pbs.append(setup_ssh_keys("employee_a_0", "root", f"database_{i}", "ubuntu"))
    for i in range(n_db):
        pbs.append(add_data(f"database_{i}", "ubuntu"))

    return topology(
        "enterprise_b",
        "Enterprise B: webservers, two employee subnets (sudobaron), database subnet",
        subnets, conns, pbs,
    )


ENTERPRISE_B = enterprise_b_topology()


# ---------------------------------------------------------------------------
# ICS: employee_one + employee_two + OT (sensors + control_hosts) + attacker
# manage hosts have netcat (baked in). manage_hosts → all sensors. 5 sensors → 5 control_hosts.
# No fixed IPs for manage_A_0 / manage_B_0 (dynamic in terraform).
# ---------------------------------------------------------------------------

def ics_topology() -> dict:
    n_emp_one = 10
    n_emp_two = 10
    n_manage = 1       # one manage host per employee subnet
    n_sensors = 20
    n_control = 5

    emp_one = [
        host(f"employee_A_{i}", "ubuntu_base_running", f"192.168.200.{10 + i}")
        for i in range(n_emp_one)
    ]
    # manage_A_0 has no fixed IP in terraform → omit ip_address
    manage_a = [host_no_ip("manage_A_0", "ubuntu_netcat_running")]

    emp_two = [
        host(f"employee_B_{i}", "ubuntu_base_running", f"192.168.201.{10 + i}")
        for i in range(n_emp_two)
    ]
    manage_b = [host_no_ip("manage_B_0", "ubuntu_netcat_running")]

    sensors = [
        host(f"sensor_{i}", "ubuntu_base_running", f"192.168.203.{10 + i}")
        for i in range(n_sensors)
    ]
    controls = [
        host(f"control_host_{i}", "ubuntu_base_running", f"192.168.203.{50 + i}")
        for i in range(n_control)
    ]

    subnets = [
        subnet("employee_one_subnet", "192.168.200.0/24", emp_one + manage_a),
        subnet("employee_two_subnet", "192.168.201.0/24", emp_two + manage_b),
        subnet("OT_subnet", "192.168.203.0/24", sensors + controls),
        ATTACKER_SUBNET,
    ]
    conns = all_pairs_connections(
        ["employee_one_subnet", "employee_two_subnet", "OT_subnet", "attacker_subnet"]
    )

    pbs = []
    # Each manage host → all sensors (SSH keys)
    for manage in ("manage_A_0", "manage_B_0"):
        for i in range(n_sensors):
            pbs.append(setup_ssh_keys(manage, "ubuntu", f"sensor_{i}", "ubuntu"))
    # sensor_0..4 → control_host_0..4 (first 5 sensors are the "critical" ones)
    for i in range(n_control):
        pbs.append(setup_ssh_keys(f"sensor_{i}", "ubuntu", f"control_host_{i}", "ubuntu"))

    return topology(
        "ics",
        "ICS-inspired: two employee subnets, OT subnet with sensors and control hosts",
        subnets, conns, pbs,
    )


ICS = ics_topology()


# ---------------------------------------------------------------------------
# Write all environments
# ---------------------------------------------------------------------------

ENVIRONMENTS = {
    "equifax_small.json": EQUIFAX_SMALL,
    "equifax_medium.json": EQUIFAX_MEDIUM,
    "equifax_large.json": EQUIFAX_LARGE,
    "dumbbell.json": DUMBBELL,
    "dumbbell_pe.json": DUMBBELL_PE,
    "chain.json": CHAIN,
    "chain_pe.json": CHAIN_PE,
    "chain_2hosts.json": CHAIN_2HOSTS,
    "star.json": STAR,
    "star_pe.json": STAR_PE,
    "enterprise_a.json": ENTERPRISE_A,
    "enterprise_b.json": ENTERPRISE_B,
    "ics.json": ICS,
}


def main():
    DST_DIR.mkdir(parents=True, exist_ok=True)
    for filename, env in ENVIRONMENTS.items():
        path = DST_DIR / filename
        with open(path, "w") as f:
            json.dump(env, f, indent=2)
        n_hosts = sum(
            len(s["hosts"])
            for net in env["networks"]
            for s in net["subnets"]
        )
        n_pbs = len(env["playbooks"])
        print(f"  {filename}: {n_hosts} hosts, {n_pbs} playbooks")
    print(f"\nDone. {len(ENVIRONMENTS)} environments written to {DST_DIR}")


if __name__ == "__main__":
    main()
