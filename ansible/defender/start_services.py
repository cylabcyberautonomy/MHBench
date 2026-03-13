from ansible.ansible_playbook import AnsiblePlaybook


class StartServices(AnsiblePlaybook):
    """Start SysFlow and Falco on a host at setup time.

    These services are installed (but not started) during the bake step.
    This playbook is run per-host at setup time so telemetry begins as soon
    as the environment is live.
    """

    def __init__(self, hosts: str | list[str]) -> None:
        self.name = "defender/start_services.yml"
        self.params = {"host": hosts}
