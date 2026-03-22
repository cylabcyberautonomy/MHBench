"""Expected VM counts per Terraform topology.

These counts include every VM that Terraform creates: topology hosts,
the perry_manager module (1 small manage host), and the attacker module
(1 large attacker), where applicable.  Used by _wait_for_servers_active()
to know when all VMs are ready without relying on the Terraform state file.

Update this dict whenever a topology's VM count changes.
"""

TOPOLOGY_VM_COUNTS: dict[str, int] = {
    # ring_host×25 + manage×1 + attacker×1
    "ring":            27,
    # same topology as ring
    "star":            27,
    # ring_host×2 + manage×1 + attacker×1
    "chain_2hosts":     4,
    # host×5 + manage×1 + attacker×1
    "openstack_dev":    7,
    # webserver×15 (small) + database×15 (tiny) + manage×1 + attacker×1
    "dumbbell":        32,
    # webserver×2 + database×4 + manage×1 + attacker×1
    "equifax_small":    8,
    # webserver×2 + database×24 + manage×1 + attacker×1
    "equifax_medium":  28,
    # webserver×2 + database×48 + manage×1 + attacker×1
    "equifax_large":   52,
    # old-style topology: 9 VMs, no perry_manager/attacker modules
    "equifax_network":  9,
    # webserver×10 + employee_a×10 + database×10 + manage×1 + attacker×1
    "enterprise_a":    32,
    # webserver×10 + employee_a×10 + employee_b×10 + database×10 + manage×1 + attacker×1
    "enterprise_b":    42,
    # employee_one×10 + manage_one×1 + employee_two×10 + manage_two×1
    # + ot_sensors×20 + ot_hosts×5 + manage×1 + attacker×1
    "enterprise_c":    49,
}
