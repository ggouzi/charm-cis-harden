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
import charmhelpers.fetch as fetch

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)

VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]
USG_PACKAGE = "usg"


class CharmCisHardeningCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        # framework.observe(self.on.config_changed, self._on_config_changed)
        framework.observe(self.on.execute_cis_action, self._cis_harden_action)
        framework.observe(self.on.install, self._on_install)
        framework.observe(self.on.execute_audit_action, self._on_audit_action)

    def _on_install(self, event):
        self.install_usg()
        self.unit.status = ops.ActiveStatus("Ready to execute CIS hardening.")
        if self.model.config["auto-harden"]:
            self.cis_harden()

    def _on_audit_action(self, event):
        self.audit("/tmp/audit.results")

    def audit(self, results_file):
        return subprocess.check_output(
            f"usg audit --tailoring-file {results_file}".split(" ")
        ).decode("utf-8")

    def install_usg(self):
        pkg = USG_PACKAGE
        self.unit.status = ops.MaintenanceStatus(f"Installing {pkg}")
        fetch.apt_install([pkg], fatal=True)

    def cis_harden(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(base64.b64decode(self.model.config["tailoring-file"]).decode("utf-8"))
            fh.flush()
            return subprocess.check_output(
                f"usg fix --tailoring-file {fh.name}".split(" ")
            ).decode("utf-8")

    def _cis_harden_action(self, event):
        self.unit.status = ops.MaintenanceStatus("Executing hardening...")
        output = self.cis_harden()
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(output)
            event.set_results({"Result": "Complete!", "Results file": fh.name})
        self.unit.status = ops.ActiveStatus("Hardening complete.")


if __name__ == "__main__":  # pragma: nocover
    ops.main(CharmCisHardeningCharm)  # type: ignore
