from pathlib import Path

import yaml

from config.config import Config


class OfflineRegistryService:

    def __init__(self, config: Config) -> None:
        self._path = config.registry.registry_dir / "offline_registry.yaml"
        self.images_dir = config.compilation.images_dir
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
        while current is not None:
            chain.append(current)
            current = self._lookup[current]["parent"]
        chain.reverse()
        return chain

    def get_location(self, name: str) -> str | None:
        return self._lookup[name]["location"]

    def update_location(self, name: str, location: str) -> None:
        self._lookup[name]["location"] = location
        self._path.write_text(yaml.dump(self._images, default_flow_style=False))

    def add_image(self, name: str, parent: str | None, playbooks: list[str]) -> None:
        entry = {"name": name, "parent": parent, "playbooks": playbooks, "location": None}
        self._images.append(entry)
        self._lookup[name] = entry
        self._path.write_text(yaml.dump(self._images, default_flow_style=False))
