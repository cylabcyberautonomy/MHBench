from ansible.ansible_playbook import AnsiblePlaybook


class StartAttacker(AnsiblePlaybook):
    def __init__(self, host: str, user: str, caldera_ip: str, caldera_port: int = 8888) -> None:
        self.name = "caldera/start_attacker.yml"
        self.params = {
            "host": host,
            "user": user,
            "caldera_ip": caldera_ip,
            "caldera_port": caldera_port,
        }
