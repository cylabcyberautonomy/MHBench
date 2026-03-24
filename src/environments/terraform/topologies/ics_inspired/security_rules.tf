### Employee One Network Rules ###
resource "openstack_networking_secgroup_v2" "employee_one_group" {
  name        = "${var.project_name}-employee_one_group"
  description = "employee one security group"
}

resource "openstack_networking_secgroup_rule_v2" "employee_one_ingress_rules" {
  for_each          = toset(["192.168.200.0/24", "192.168.201.0/24", "192.168.203.0/24"])
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.employee_one_group.id
}

resource "openstack_networking_secgroup_rule_v2" "employee_one_egress_rules" {
  for_each          = toset(["192.168.200.0/24", "192.168.201.0/24", "192.168.203.0/24"])
  direction         = "egress"
  ethertype         = "IPv4"
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.employee_one_group.id
}

### Employee Two Network Rules ###
resource "openstack_networking_secgroup_v2" "employee_two_group" {
  name        = "${var.project_name}-employee_two_group"
  description = "employee two security group"
}

resource "openstack_networking_secgroup_rule_v2" "employee_two_ingress_rules" {
  for_each          = toset(["192.168.200.0/24", "192.168.201.0/24", "192.168.203.0/24"])
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.employee_two_group.id
}

resource "openstack_networking_secgroup_rule_v2" "employee_two_egress_rules" {
  for_each          = toset(["192.168.200.0/24", "192.168.201.0/24", "192.168.203.0/24"])
  direction         = "egress"
  ethertype         = "IPv4"
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.employee_two_group.id
}

### OT Network Rules ###
resource "openstack_networking_secgroup_v2" "ot_group" {
  name        = "${var.project_name}-ot_group"
  description = "OT network security group"
}

resource "openstack_networking_secgroup_rule_v2" "ot_ingress_rules" {
  for_each          = toset(["192.168.200.0/24", "192.168.201.0/24", "192.168.203.0/24"])
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.ot_group.id
}

resource "openstack_networking_secgroup_rule_v2" "ot_egress_rules" {
  for_each          = toset(["192.168.200.0/24", "192.168.201.0/24", "192.168.203.0/24"])
  direction         = "egress"
  ethertype         = "IPv4"
  remote_ip_prefix  = each.value
  security_group_id = openstack_networking_secgroup_v2.ot_group.id
}
