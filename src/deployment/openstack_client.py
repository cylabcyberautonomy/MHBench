from __future__ import annotations

import logging

import openstack
from openstack.connection import Connection

from config.config import OpenStackConfig

logger = logging.getLogger(__name__)


def build_connection(cfg: OpenStackConfig) -> Connection:
    logger.debug("Connecting to cloud '%s'", cfg.cloud)
    # compute microversion >= 2.90 so create_server's `hostname` (the guest hostname, distinct from the
    # experiment-prefixed display name) is actually sent to Nova.
    kwargs = {"cloud": cfg.cloud, "compute_api_version": "2.90"}
    if cfg.clouds_yaml:
        kwargs["config_files"] = [cfg.clouds_yaml]
    conn = openstack.connect(**kwargs)
    logger.debug("Connection established.")
    return conn
