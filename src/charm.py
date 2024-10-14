#!/usr/bin/env python3
# Copyright 2024 pjds
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm CIS Hardening

Refer to the following tutorial that will help you
develop a new k8s charm using the Operator Framework:

https://juju.is/docs/sdk/create-a-minimal-kubernetes-charm
"""

import logging
import tempfile
import base64
import subprocess
import ops

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)

VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]


class CharmCisHardeningCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        # framework.observe(self.on.config_changed, self._on_config_changed)
        framework.observe(self.on.execute_cis_action, self._cis_harden_action)
        framework.observe(self.on.install, self._on_install)

    def _on_install(self, event):
        self.unit.status = ops.ActiveStatus("Ready to execute CIS hardening.")
        if self.model.config["auto-harden"]:
            self.cis_harden()

    def cis_harden(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(base64.b64decode(self.model.config["tailoring-file"]).decode('utf-8'))
            fh.flush()
            return subprocess.check_output(f"usg fix --tailoring-file {fh.name}".split(" "))

    def _cis_harden_action(self, event):
        self.unit.status = ops.ActiveStatus("Executing hardening...")
        self.cis_harden()
        event.set_results({"result": "Completed!"})
        logger.debug("Hardening action completed")


if __name__ == "__main__":  # pragma: nocover
    ops.main(CharmCisHardeningCharm)  # type: ignore
