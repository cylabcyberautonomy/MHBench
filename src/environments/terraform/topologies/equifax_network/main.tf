######### Setup Networking #########
# External network is not managed by terraform, need to set as datasource
data "openstack_networking_network_v2" "external_network" {
  name = "external"
}
module "manage_rules" {
  source = "../modules/"
}

resource "openstack_networking_network_v2" "manage_network" {
  name           = "${var.project_name}-manage_network"
  admin_state_up = "true"
}

resource "openstack_networking_network_v2" "webserver_network" {
  name           = "${var.project_name}-webserver_network"
  admin_state_up = "true"
  description    = "The external webserver network"
}

resource "openstack_networking_network_v2" "critical_company_network" {
  name           = "${var.project_name}-critical_company_network"
  admin_state_up = "true"
  description    = "The corporate network with critical data"
}

resource "openstack_networking_network_v2" "attacker_network" {
  name           = "${var.project_name}-attacker_network"
  admin_state_up = "true"
  description    = "The attacker network"
}

### Subnets ###
resource "openstack_networking_subnet_v2" "manage" {
  name            = "${var.project_name}-manage"
  network_id      = openstack_networking_network_v2.manage_network.id
  cidr            = "192.168.198.0/24"
  ip_version      = 4
  dns_nameservers = ["8.8.8.8"]
}

resource "openstack_networking_subnet_v2" "webserver_subnet" {
  name            = "${var.project_name}-webserver_network"
  network_id      = openstack_networking_network_v2.webserver_network.id
  cidr            = "192.168.200.0/24"
  ip_version      = 4
  dns_nameservers = ["8.8.8.8"]
}

resource "openstack_networking_subnet_v2" "critical_company_subnet" {
  name            = "${var.project_name}-critical_company_network"
  network_id      = openstack_networking_network_v2.critical_company_network.id
  cidr            = "192.168.201.0/24"
  ip_version      = 4
  dns_nameservers = ["8.8.8.8"]
}

resource "openstack_networking_subnet_v2" "attacker_subnet" {
  name            = "${var.project_name}-attacker_network"
  network_id      = openstack_networking_network_v2.attacker_network.id
  cidr            = "192.168.202.0/24"
  ip_version      = 4
  dns_nameservers = ["8.8.8.8"]
}

### Ports ###
# Host Ports
resource "openstack_networking_port_v2" "manage_port_host" {
  name               = "${var.project_name}-manage_port_host"
  network_id         = openstack_networking_network_v2.manage_network.id
  admin_state_up     = "true"
  security_group_ids = ["${openstack_networking_secgroup_v2.manage_freedom.id}"]

  fixed_ip {
    subnet_id = openstack_networking_subnet_v2.manage.id
  }
}

resource "openstack_networking_port_v2" "webserver_A_port" {
  name           = "${var.project_name}-webserver_A_port"
  network_id     = openstack_networking_network_v2.webserver_network.id
  admin_state_up = "true"
  security_group_ids = [
    "${openstack_networking_secgroup_v2.talk_to_manage.id}",
    "${openstack_networking_secgroup_v2.webserver.id}"
  ]

  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.webserver_subnet.id
    ip_address = "192.168.200.3"
  }
}

resource "openstack_networking_port_v2" "webserver_B_port" {
  name           = "${var.project_name}-webserver_B_port"
  network_id     = openstack_networking_network_v2.webserver_network.id
  admin_state_up = "true"
  security_group_ids = [
    "${openstack_networking_secgroup_v2.talk_to_manage.id}",
    "${openstack_networking_secgroup_v2.webserver.id}"
  ]

  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.webserver_subnet.id
    ip_address = "192.168.200.4"
  }
}

resource "openstack_networking_port_v2" "webserver_C_port" {
  name           = "${var.project_name}-webserver_C_port"
  network_id     = openstack_networking_network_v2.webserver_network.id
  admin_state_up = "true"
  security_group_ids = [
    "${openstack_networking_secgroup_v2.talk_to_manage.id}",
    "${openstack_networking_secgroup_v2.webserver.id}"
  ]

  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.webserver_subnet.id
    ip_address = "192.168.200.5"
  }
}

resource "openstack_networking_port_v2" "employee_A_port" {
  name           = "${var.project_name}-employee_A_port"
  network_id     = openstack_networking_network_v2.critical_company_network.id
  admin_state_up = "true"
  security_group_ids = [
    "${openstack_networking_secgroup_v2.talk_to_manage.id}",
    "${openstack_networking_secgroup_v2.critical_company.id}"
  ]

  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.critical_company_subnet.id
    ip_address = "192.168.201.3"
  }
}

resource "openstack_networking_port_v2" "employee_B_port" {
  name           = "${var.project_name}-employee_B_port"
  network_id     = openstack_networking_network_v2.critical_company_network.id
  admin_state_up = "true"
  security_group_ids = [
    "${openstack_networking_secgroup_v2.talk_to_manage.id}",
    "${openstack_networking_secgroup_v2.critical_company.id}"
  ]

  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.critical_company_subnet.id
    ip_address = "192.168.201.4"
  }
}

resource "openstack_networking_port_v2" "database_A_port" {
  name           = "${var.project_name}-database_A_port"
  network_id     = openstack_networking_network_v2.critical_company_network.id
  admin_state_up = "true"
  security_group_ids = [
    "${openstack_networking_secgroup_v2.talk_to_manage.id}",
    "${openstack_networking_secgroup_v2.critical_company.id}"
  ]

  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.critical_company_subnet.id
    ip_address = "192.168.201.5"
  }
}

resource "openstack_networking_port_v2" "database_B_port" {
  name           = "${var.project_name}-database_B_port"
  network_id     = openstack_networking_network_v2.critical_company_network.id
  admin_state_up = "true"
  security_group_ids = [
    "${openstack_networking_secgroup_v2.talk_to_manage.id}",
    "${openstack_networking_secgroup_v2.critical_company.id}"
  ]

  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.critical_company_subnet.id
    ip_address = "192.168.201.6"
  }
}

resource "openstack_networking_port_v2" "attacker_port" {
  name           = "${var.project_name}-attacker_port"
  network_id     = openstack_networking_network_v2.attacker_network.id
  admin_state_up = "true"
  security_group_ids = [
    "${openstack_networking_secgroup_v2.talk_to_manage.id}",
    "${openstack_networking_secgroup_v2.attacker.id}"
  ]

  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.attacker_subnet.id
    ip_address = "192.168.202.3"
  }
}

### Routers ###
resource "openstack_networking_router_v2" "router_external" {
  name                = "${var.project_name}-router_external"
  admin_state_up      = true
  external_network_id = data.openstack_networking_network_v2.external_network.id
}

resource "openstack_networking_router_interface_v2" "router_interface_manage_external" {
  router_id = openstack_networking_router_v2.router_external.id
  subnet_id = openstack_networking_subnet_v2.manage.id
}

# Connect subnets
resource "openstack_networking_router_interface_v2" "router_interface_manage_company" {
  router_id = openstack_networking_router_v2.router_external.id
  subnet_id = openstack_networking_subnet_v2.webserver_subnet.id
}

resource "openstack_networking_router_interface_v2" "router_interface_manage_datacenter" {
  router_id = openstack_networking_router_v2.router_external.id
  subnet_id = openstack_networking_subnet_v2.critical_company_subnet.id
}

resource "openstack_networking_router_interface_v2" "router_interface_manage_attacker" {
  router_id = openstack_networking_router_v2.router_external.id
  subnet_id = openstack_networking_subnet_v2.attacker_subnet.id
}

######### Setup Compute #########

### Management Host ###
resource "openstack_compute_instance_v2" "manage_host" {
  name        = "${var.project_name}-manage_host"
  image_name  = var.images.ubuntu_pip
  flavor_name = var.flavors.small
  key_pair    = var.perry_key_name

  network {
    port = openstack_networking_port_v2.manage_port_host.id
  }

  availability_zone = var.availability_zone != "" ? var.availability_zone : null
}

resource "openstack_networking_floatingip_v2" "manage_floating_ip" {
  pool = "external"
}

resource "openstack_networking_floatingip_associate_v2" "fip_manage" {
  floating_ip = openstack_networking_floatingip_v2.manage_floating_ip.address
  port_id     = openstack_networking_port_v2.manage_port_host.id
}

### Webserver Subnet Hosts ###
resource "openstack_compute_instance_v2" "webserver_A" {
  name        = "${var.project_name}-webserver_A"
  image_name  = var.images.ubuntu_pip
  flavor_name = var.flavors.small
  key_pair    = var.perry_key_name

  network {
    port = openstack_networking_port_v2.webserver_A_port.id
  }

  availability_zone = var.availability_zone != "" ? var.availability_zone : null
}

resource "openstack_compute_instance_v2" "webserver_B" {
  name        = "${var.project_name}-webserver_B"
  image_name  = var.images.ubuntu_pip
  flavor_name = var.flavors.small
  key_pair    = var.perry_key_name

  network {
    port = openstack_networking_port_v2.webserver_B_port.id
  }

  availability_zone = var.availability_zone != "" ? var.availability_zone : null
}

resource "openstack_compute_instance_v2" "webserver_C" {
  name        = "${var.project_name}-webserver_C"
  image_name  = var.images.ubuntu_pip
  flavor_name = var.flavors.small
  key_pair    = var.perry_key_name

  network {
    port = openstack_networking_port_v2.webserver_C_port.id
  }

  availability_zone = var.availability_zone != "" ? var.availability_zone : null
}

### Corporate Subnet Hosts ###
resource "openstack_compute_instance_v2" "employee_A" {
  name        = "${var.project_name}-employee_A"
  image_name  = var.images.ubuntu_pip
  flavor_name = var.flavors.small
  key_pair    = var.perry_key_name

  network {
    port = openstack_networking_port_v2.employee_A_port.id
  }

  availability_zone = var.availability_zone != "" ? var.availability_zone : null
}

resource "openstack_compute_instance_v2" "employee_B" {
  name        = "${var.project_name}-employee_B"
  image_name  = var.images.ubuntu_pip
  flavor_name = var.flavors.small
  key_pair    = var.perry_key_name

  network {
    port = openstack_networking_port_v2.employee_B_port.id
  }

  availability_zone = var.availability_zone != "" ? var.availability_zone : null
}

resource "openstack_compute_instance_v2" "database_A" {
  name        = "${var.project_name}-database_A"
  image_name  = var.images.ubuntu_pip
  flavor_name = var.flavors.small
  key_pair    = var.perry_key_name

  network {
    port = openstack_networking_port_v2.database_A_port.id
  }

  availability_zone = var.availability_zone != "" ? var.availability_zone : null
}

resource "openstack_compute_instance_v2" "database_B" {
  name        = "${var.project_name}-database_B"
  image_name  = var.images.ubuntu_pip
  flavor_name = var.flavors.small
  key_pair    = var.perry_key_name

  network {
    port = openstack_networking_port_v2.database_B_port.id
  }

  availability_zone = var.availability_zone != "" ? var.availability_zone : null
}

### Attacker Subnet Hosts ###
resource "openstack_compute_instance_v2" "attacker" {
  name        = "${var.project_name}-attacker"
  image_name  = var.images.ubuntu_pip
  flavor_name = var.flavors.small
  key_pair    = var.perry_key_name

  network {
    port = openstack_networking_port_v2.attacker_port.id
  }

  availability_zone = var.availability_zone != "" ? var.availability_zone : null
}
