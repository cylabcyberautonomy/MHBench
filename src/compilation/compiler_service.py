from __future__ import annotations

import logging
from pathlib import Path

from config.config import Config
from src.compilation.image_compiler import compile_image as _bake
from src.compilation.offline_registry_service import OfflineRegistryService
from src.playbooks.playbook_registry_service import PlaybookRegistryService

logger = logging.getLogger(__name__)


class CompilerService:

    def __init__(
        self,
        config: Config,
        offline_registry: OfflineRegistryService,
        playbook_registry: PlaybookRegistryService,
    ) -> None:
        self._images_dir = config.compilation.images_dir
        self._offline = offline_registry
        self._playbooks = playbook_registry

    def compile_image(self, name: str, force: bool = False) -> None:
        output = self._images_dir / f"{name}.qcow2"
        if not force and output.exists():
            logger.info("'%s' already compiled — skipping.", name)
            return
        parent = self._offline.get_parent(name)
        if parent is None:
            raise ValueError(f"'{name}' is a root image and cannot be compiled.")
        parent_location = self._offline.get_location(parent)
        if not parent_location or not Path(parent_location).exists():
            raise RuntimeError(f"Parent '{parent}' of '{name}' has not been compiled yet.")
        playbook_paths = [self._playbooks.get_path(pb) for pb in self._offline.get_playbooks(name)]
        disk_size_gb = self._offline.get_disk_size_gb(name)
        logger.info("Compiling '%s' from parent '%s'.", name, parent)
        _bake(Path(parent_location), playbook_paths, output, disk_size_gb=disk_size_gb)
        self._offline.update_location(name, str(output))

    def compile_with_ancestors(self, name: str, force: bool = False) -> None:
        chain = self._offline.get_ancestor_chain(name)
        for image_name in chain[1:]:
            self.compile_image(image_name, force=force)

    def compile_all(self, force: bool = False) -> None:
        images = self._offline.list_images()
        ordered = sorted(images, key=lambda n: len(self._offline.get_ancestor_chain(n)))
        for name in ordered:
            if self._offline.get_parent(name) is None:
                continue
            self.compile_image(name, force=force)
