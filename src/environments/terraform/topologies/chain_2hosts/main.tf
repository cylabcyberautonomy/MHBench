######### Setup Networking #########
module "perry_manager" {
  source   = "../modules/perry_manager"
  key_name = var.perry_key_name
  images   = var.images
  flavors  = var.flavors
  availability_zone      = var.availability_zone
  name_prefix            = var.project_name
}

module "attacker" {
  source             = "../modules/attacker"
  router_external_id = module.perry_manager.router_external_id
  key_name           = var.perry_key_name
  images             = var.images
  flavors            = var.flavors
  availability_zone      = var.availability_zone
  name_prefix            = var.project_name
}

resource "openstack_networking_network_v2" "ring_network" {
  name           = "${var.project_name}-ring_network"
  admin_state_up = "true"
  description    = "Ring"
}

### Subnets ###
resource "openstack_networking_subnet_v2" "ring_subnet" {
  name            = "${var.project_name}-ring_subnet"
  network_id      = openstack_networking_network_v2.ring_network.id
  cidr            = "192.168.200.0/24"
  ip_version      = 4
  dns_nameservers = ["8.8.8.8"]
}


### Routers ###
# Connect subnets
resource "openstack_networking_router_interface_v2" "router_interface_manage_company" {
  router_id = module.perry_manager.router_external_id
  subnet_id = openstack_networking_subnet_v2.ring_subnet.id
}

######### Setup Compute #########
### Ring Subnet Hosts ###
resource "openstack_compute_instance_v2" "ring_host" {
  count       = 2
  name        = "${var.project_name}-host_${count.index}"
  image_name  = var.images.host_baked != "" ? var.images.host_baked : var.images.ubuntu
  flavor_name = var.flavors.tiny
  key_pair    = var.perry_key_name
  security_groups = [
    module.perry_manager.talk_to_manage_name,
    openstack_networking_secgroup_v2.employee_one_group.name
  ]

  network {
    name = "${var.project_name}-ring_network"
    // sequential ips
    fixed_ip_v4 = "192.168.200.${count.index + 10}"
  }

  availability_zone = var.availability_zone != "" ? var.availability_zone : null

  depends_on = [openstack_networking_subnet_v2.ring_subnet]
}
