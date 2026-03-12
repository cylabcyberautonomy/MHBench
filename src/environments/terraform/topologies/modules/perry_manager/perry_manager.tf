# External network is not managed by terraform, need to set as datasource
data "openstack_networking_network_v2" "external_network" {
  name = "external"
}

variable "key_name" {
  description = "The name of the key pair to use for the instance"
}
variable "images" {
  type = object({
    ubuntu     = string
    ubuntu_pip = string
    kali       = string
  })
}
variable "flavors" {
  type = object({
    tiny   = string
    small  = string
    medium = string
    large  = string
    huge   = string
  })
}

output "external_network_id" {
  value = data.openstack_networking_network_v2.external_network.id
}

output "talk_to_manage_id" {
  value = openstack_networking_secgroup_v2.talk_to_manage.id
}

output "talk_to_manage_name" {
  value = openstack_networking_secgroup_v2.talk_to_manage.name
}

output "manage_freedom_id" {
  value = openstack_networking_secgroup_v2.manage_freedom.id
}
output "manage_freedom_name" {
  value = openstack_networking_secgroup_v2.manage_freedom.name
}

output "router_external_id" {
  value = openstack_networking_router_v2.router_external.id
}

### Network ###
variable "name_prefix" {
  type        = string
  description = "Project name prefix for VM names to avoid cross-project conflicts."
  default     = "perry"
}

variable "compute_node_hostnames" {
  type        = list(string)
  description = "Physical compute node hostnames to pin VMs to via Nova scheduler hints. Empty list = no pinning."
  default     = []
}

resource "openstack_networking_network_v2" "manage_network" {
  name           = "${var.name_prefix}-manage_network"
  admin_state_up = "true"
}

resource "openstack_networking_subnet_v2" "manage" {
  name            = "${var.name_prefix}-manage"
  network_id      = openstack_networking_network_v2.manage_network.id
  cidr            = "192.168.198.0/24"
  ip_version      = 4
  dns_nameservers = ["8.8.8.8"]
}

resource "openstack_networking_router_v2" "router_external" {
  name                = "${var.name_prefix}-router_external"
  admin_state_up      = true
  external_network_id = data.openstack_networking_network_v2.external_network.id
}

resource "openstack_networking_router_interface_v2" "router_interface_manage_external" {
  router_id = openstack_networking_router_v2.router_external.id
  subnet_id = openstack_networking_subnet_v2.manage.id
}

### Host ###
resource "openstack_compute_instance_v2" "manage_host" {
  name        = "${var.name_prefix}-manage_host"
  image_name  = var.images.ubuntu
  flavor_name = var.flavors.small
  key_pair    = var.key_name
  security_groups = [
    openstack_networking_secgroup_v2.talk_to_manage.name,
    openstack_networking_secgroup_v2.manage_freedom.name
  ]

  network {
    name        = "${var.name_prefix}-manage_network"
    fixed_ip_v4 = "192.168.198.14"
  }

  dynamic "scheduler_hints" {
    for_each = length(var.compute_node_hostnames) > 0 ? [1] : []
    content {
      additional_properties = {
        "force_hosts" = join(",", var.compute_node_hostnames)
      }
    }
  }

  depends_on = [openstack_networking_subnet_v2.manage]
}

resource "openstack_networking_floatingip_v2" "manage_floating_ip" {
  pool = "external"
}

resource "openstack_compute_floatingip_associate_v2" "fip_manage" {
  floating_ip = openstack_networking_floatingip_v2.manage_floating_ip.address
  instance_id = openstack_compute_instance_v2.manage_host.id
}
