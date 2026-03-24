from ansible.ansible_playbook import AnsiblePlaybook


class WaitForPort(AnsiblePlaybook):
    def __init__(self, host: str, port: int) -> None:
        self.name = "deployment_instance/wait_for_port/wait_for_port.yml"
        self.params = {
            "host": host,
            "port": port,
        }
