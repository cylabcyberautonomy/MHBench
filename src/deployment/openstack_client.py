from __future__ import annotations

import logging

import openstack
from openstack.connection import Connection

from config.config import OpenStackConfig

logger = logging.getLogger(__name__)


def build_connection(cfg: OpenStackConfig) -> Connection:
    logger.debug("Connecting to cloud '%s'", cfg.cloud)
    kwargs = {"cloud": cfg.cloud}
    if cfg.clouds_yaml:
        kwargs["config_files"] = [cfg.clouds_yaml]
    conn = openstack.connect(**kwargs)
    logger.debug("Connection established.")
    return conn
