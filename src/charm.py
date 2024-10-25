#!/usr/bin/env python3
# Copyright 2024 pjds
# See LICENSE file for licensing details.

"""Charm CIS Hardening

This charm implements CIS (Center for Internet Security) hardening for Juju units.
It provides capabilities to install, configure, and audit security configurations
based on CIS benchmarks.
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
AUDIT_RESULTS_PATH = "/tmp/audit.results"


class CharmCisHardeningCharm(ops.CharmBase):
    """A charm for implementing CIS hardening standards on units."""

    _stored = ops.framework.StoredState()

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self._stored.set_default(hardening_status=False)

        framework.observe(self.on.execute_cis_action, self._cis_harden_action)
        framework.observe(self.on.install, self._on_install)
        framework.observe(self.on.execute_audit_action, self._on_audit_action)
        framework.observe(self.on.start, self._on_start)

    def _on_install(self, event):
        try:
            self.unit.status = ops.MaintenanceStatus("Installing dependencies...")
            self.install_usg()

            self.unit.status = ops.BlockedStatus("Ready for CIS hardening. Run 'execute-cis' action")

            if self.model.config["auto-harden"]:
                self.unit.status = ops.MaintenanceStatus("Auto-hardening enabled, starting hardening...")
                self.cis_harden()
        except Exception as e:
            logger.error(f"Installation failed: {str(e)}")
            self.unit.status = ops.BlockedStatus(f"Install failed: {str(e)}")

    def _on_start(self, event):
        # Workaround needed https://chat.canonical.com/canonical/pl/rr9su5ceh3r98r5jbiuu6989wr
        subprocess.check_output(
            "sysctl --system".split(" ")
        ).decode("utf-8")
        if self._stored.hardening_status:
            self.unit.status = ops.ActiveStatus("Unit is hardened. Use 'execute-audit' action to check compliance")
        else:
            self.unit.status = ops.BlockedStatus("Ready for CIS hardening. Run 'execute-cis' action")

    def _on_audit_action(self, event):
        try:
            results = self.audit(AUDIT_RESULTS_PATH)
            event.set_results({
                "result": results,
                "file": AUDIT_RESULTS_PATH
            })
        except Exception as e:
            logger.error(f"Audit failed: {str(e)}")
            event.fail(f"Audit failed: {str(e)}")

    def audit(self, results_file):
        try:
            return subprocess.check_output(
                f"usg audit --tailoring-file {results_file}".split(" ")
            ).decode("utf-8")
        except subprocess.CalledProcessError as e:
            logger.error(f"Audit failed: {str(e)}")
            raise

    def install_usg(self):
        try:
            fetch.apt_update()
            fetch.apt_install([USG_PACKAGE], fatal=True)
        except Exception as e:
            logger.error(f"Failed to install {USG_PACKAGE}: {str(e)}")
            raise

    def cis_harden(self):
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as fh:
                tailoring_content = base64.b64decode(
                    self.model.config["tailoring-file"]
                ).decode("utf-8")
                fh.write(tailoring_content)
                fh.flush()
                cmd = ["usg", "fix", "--tailoring-file", fh.name]
                return subprocess.check_output(cmd, text=True)
        except Exception as e:
            logger.error(f"Hardening failed: {str(e)}")
            raise

    def _cis_harden_action(self, event):
        self.unit.status = ops.MaintenanceStatus("Executing hardening...")
        self._stored.hardening_status = False

        try:
            output = self.cis_harden()
            filename = None
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as fh:
                fh.write(output)
                filename = fh.name
            event.set_results({
                "result": "Complete! Please reboot the unit",
                "file": filename
            })
            self.unit.status = ops.BlockedStatus(
                f"Hardening complete. Results in {filename}. Please reboot the unit"
            )
            self._stored.hardening_status = True

        except Exception as e:
            logger.error(f"Hardening action failed: {str(e)}")
            event.fail(f"Hardening failed: {str(e)}")
            self.unit.status = ops.BlockedStatus("Hardening failed. Check juju debug-log")


if __name__ == "__main__":
    ops.main(CharmCisHardeningCharm)
