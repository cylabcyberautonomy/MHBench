from pathlib import Path

import yaml

from config.config import Config


class OnlineRegistryService:

    def __init__(self, config: Config) -> None:
        self._path = config.registry.registry_dir / "online_registry.yaml"
        self._images: list[dict] = yaml.safe_load(self._path.read_text())
        self._lookup: dict[str, dict] = {img["name"]: img for img in self._images}

    def get_parent(self, name: str) -> str | None:
        return self._lookup[name]["parent"]

    def list_images(self) -> list[str]:
        return [img["name"] for img in self._images]

    def get_playbooks(self, name: str) -> list[str]:
        return list(self._lookup[name]["playbooks"])

    def get_ancestor_chain(self, name: str) -> list[str]:
        chain, current = [], name
        while current is not None and current in self._lookup:
            chain.append(current)
            current = self._lookup[current]["parent"]
        chain.reverse()
        return chain

    def get_base_image(self, name: str) -> str:
        if name not in self._lookup:
            return name
        chain = self.get_ancestor_chain(name)
        return self._lookup[chain[0]]["parent"]

    def get_location(self, name: str) -> str | None:
        return self._lookup[name]["location"]

    def update_location(self, name: str, location: str) -> None:
        self._lookup[name]["location"] = location
        self._write()

    def add_image(self, name: str, parent: str | None, playbooks: list[str]) -> None:
        entry = {"name": name, "parent": parent, "playbooks": playbooks, "location": None}
        self._images.append(entry)
        self._lookup[name] = entry
        self._write()

    def get_runtime_playbooks(self, name: str) -> list[str]:
        if name not in self._lookup:
            return []
        playbooks = []
        for entry_name in self.get_ancestor_chain(name):
            playbooks.extend(self._lookup[entry_name]["playbooks"])
        return playbooks

    def _write(self) -> None:
        ordered = [
            {"name": i["name"], "parent": i["parent"], "playbooks": i["playbooks"], "location": i["location"]}
            for i in self._images
        ]
        self._path.write_text(yaml.dump(ordered, default_flow_style=False, sort_keys=False))
