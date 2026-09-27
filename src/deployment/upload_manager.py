from __future__ import annotations

import logging
from pathlib import Path

from openstack.connection import Connection

from config.config import Config

logger = logging.getLogger(__name__)


class UploadManager:

    def __init__(self, conn: Connection, config: Config, offline_registry=None) -> None:
        self._conn = conn
        self._offline = offline_registry

    def upload_image(self, name: str, force: bool = False) -> None:
        """Upload by resolving the on-disk location from the offline registry.

        Kept for callers that construct UploadManager with an offline registry.
        """
        if self._offline is None:
            raise ValueError("UploadManager needs an offline registry to resolve a location, "
                             "or call upload_image_from(name, location).")
        location = self._offline.get_location(name)
        self.upload_image_from(name, location, force=force)

    def upload_image_from(self, name: str, location: str | None, force: bool = False) -> None:
        if not location or not Path(location).exists():
            logger.warning("'%s' is not compiled — skipping upload.", name)
            return

        existing = self._conn.image.find_image(name)
        if existing and not force:
            logger.info("'%s' already in Glance — skipping (use force=True to re-upload).", name)
            return
        if existing and force:
            self.delete_image(name)

        logger.info("Uploading '%s' → Glance.", name)
        image = self._conn.image.create_image(
            name=name,
            filename=location,
            disk_format="qcow2",
            container_format="bare",
            visibility="public",
            wait=True,
        )
        logger.info("Uploaded '%s' (id: %s).", name, image.id)

    def delete_image(self, name: str) -> None:
        existing = self._conn.image.find_image(name)
        if not existing:
            logger.warning("'%s' not found in Glance — nothing to delete.", name)
            return
        self._conn.image.delete_image(existing.id, ignore_missing=False)
        logger.info("Deleted '%s' from Glance.", name)
