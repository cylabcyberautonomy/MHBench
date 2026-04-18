from __future__ import annotations

import logging

import openstack
from openstack.connection import Connection

from config.config import OpenStackConfig

logger = logging.getLogger(__name__)


def build_connection(cfg: OpenStackConfig) -> Connection:
    logger.debug("Connecting to %s (project: %s)", cfg.auth_url, cfg.project_name)
    conn = openstack.connect(
        auth_url=cfg.auth_url,
        username=cfg.username,
        password=cfg.password,
        project_name=cfg.project_name,
        region_name=cfg.region,
        identity_api_version=3,
        user_domain_name="Default",
        project_domain_name="Default",
        api_timeout=cfg.client_timeout,
    )
    logger.debug("Connection established.")
    return conn
