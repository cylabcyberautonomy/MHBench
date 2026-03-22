# input variables
variable "router_external_id" {
  description = "The external router"
}
variable "key_name" {
  description = "The key name to use for the instances"
}
variable "images" {
  type = object({
    ubuntu            = string
    ubuntu_pip        = string
    kali              = string
    webserver_baked   = optional(string, "")
    database_baked    = optional(string, "")
    employee_baked    = optional(string, "")
    attacker_baked    = optional(string, "")
    manage_host_baked = optional(string, "")
    host_baked        = optional(string, "")
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

variable "name_prefix" {
  type        = string
  description = "Project name prefix for VM names to avoid cross-project conflicts."
  default     = "perry"
}
resource "openstack_networking_network_v2" "attacker_network" {
  name           = "${var.name_prefix}-attacker_network"
  admin_state_up = "true"
  description    = "The attacker network"
}

resource "openstack_networking_subnet_v2" "attacker_subnet" {
  name            = "${var.name_prefix}-attacker_subnet"
  network_id      = openstack_networking_network_v2.attacker_network.id
  cidr            = "192.168.202.0/24"
  ip_version      = 4
  dns_nameservers = ["8.8.8.8"]
}

resource "openstack_networking_router_interface_v2" "router_interface_manage_attacker" {
  router_id = var.router_external_id
  subnet_id = openstack_networking_subnet_v2.attacker_subnet.id
}

### Attacker Subnet Hosts ###
resource "openstack_compute_instance_v2" "attacker" {
  name        = "${var.name_prefix}-attacker"
  image_name  = var.images.attacker_baked != "" ? var.images.attacker_baked : var.images.kali
  flavor_name = var.flavors.large
  key_pair    = var.key_name
  security_groups = [
    openstack_networking_secgroup_v2.attacker.name
  ]
  network {
    name        = "${var.name_prefix}-attacker_network"
    fixed_ip_v4 = "192.168.202.100"
  }



  depends_on = [openstack_networking_subnet_v2.attacker_subnet]
}
