import json
from pathlib import Path

from config.config import Config


class PlaybookRegistryService:

    def __init__(self, config: Config) -> None:
        self._path = config.registry.registry_dir / "playbooks.json"
        self._lookup: dict[str, str] = json.loads(self._path.read_text())
        self.playbooks_dir = config.playbooks.playbooks_dir

    def get_path(self, name: str) -> Path:
        return Path(self._lookup[name])

    def register_playbook(self, name: str, path: str) -> None:
        self._lookup[name] = path
        self._path.write_text(json.dumps(self._lookup, indent=2))
