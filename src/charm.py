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
from xml.dom import minidom
import charmhelpers.fetch as fetch
from datetime import datetime

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)

VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]
USG_PACKAGE = "usg"
AUDIT_HTML_RESULTS_PATH = "/tmp/audit.results.html"
AUDIT_XML_RESULTS_PATH = "/tmp/audit.results.xml"


class CharmCisHardeningCharm(ops.CharmBase):
    """A charm for implementing CIS hardening standards on units."""

    _stored = ops.framework.StoredState()

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self._stored.set_default(
            hardening_status=False,
            audit_status=False,
            last_hardening_timestamp=None,
            last_audit_timestamp=None,
            last_audit_files=[],
            last_audit_result=None
        )

        # Hooks
        framework.observe(self.on.config_changed, self._on_config_changed)
        framework.observe(self.on.install, self._on_install)
        framework.observe(self.on.start, self._on_start)

        # Actions
        framework.observe(self.on.audit_action, self._on_audit_action)
        framework.observe(self.on.harden_action, self._on_hardening_action)
        framework.observe(self.on.get_status_action, self._on_get_status_action)
        framework.observe(self.on.get_results_action, self._on_get_results_action)

    def install_usg(self):
        try:
            fetch.apt_update()
            fetch.apt_install([USG_PACKAGE], fatal=True)
        except Exception as e:
            logger.error(f"Failed to install {USG_PACKAGE}: {str(e)}")
            raise

    def is_configuration_set(self, config_key):
        config = self.model.config
        tailoring_file = config.get(config_key, "")
        if not tailoring_file.strip():
            return False
        return True

    def check_state(self):
        if self._stored.hardening_status:
            if self._stored.audit_status:
                self.unit.status = ops.ActiveStatus(f"Audit finished. Result file: {AUDIT_HTML_RESULTS_PATH}")
            else:
                self.unit.status = ops.ActiveStatus("Unit is hardened. Use 'audit' action to check compliance")
            return
        if not self.is_configuration_set("tailoring-file"):
            logger.error("Tailoring-file is not set")
            self.unit.status = ops.BlockedStatus("Cannot run hardening. Please configure a tailoring-file")
        else:
            self.unit.status = ops.ActiveStatus("Ready for CIS hardening. Run 'harden' action")

    def parse_audit_results(self, filename):
        """
        Parses XML result file to get the percentage of passed rules
        Returns only the value of the score tag
        This is a nice-to-have and should not block the action.
        Thus Returns None if any error is raised. Clean memory to avoid leaks
        """
        try:
            with open(filename, 'r') as file:
                xml_content = file.read()

            # Parse the XML content to get the total score of the audit (e.g 99%)
            doc = minidom.parseString(xml_content)
            score_elements = doc.getElementsByTagName('score')

            if score_elements:
                return score_elements[0].firstChild.nodeValue
            return None
        except Exception as e:
            logger.error(f"XML parsing failed: {str(e)}")
            return None
        finally:
            # Clean up to prevent memory leaks
            if 'doc' in locals():
                doc.unlink()

    def _on_install(self, event):
        try:
            self.unit.status = ops.MaintenanceStatus("Installing dependencies...")
            self.install_usg()
            self.unit.status = ops.ActiveStatus("Ready for CIS hardening. Run 'harden' action")

            if self.model.config["auto-harden"]:
                self.unit.status = ops.MaintenanceStatus("Auto-hardening enabled, starting hardening...")
                self.cis_harden()
        except Exception as e:
            logger.error(f"Installation failed: {str(e)}")
            self.unit.status = ops.BlockedStatus(f"Install failed: {str(e)}")

    def _on_start(self, event):
        # Workaround needed to make sure all sysctl settings are correctly loaded
        subprocess.check_output(
            "sysctl --system".split(" ")
        ).decode("utf-8")
        self.check_state()

    def _on_config_changed(self, event):
        self.check_state()

    def _on_audit_action(self, event):
        if not self.is_configuration_set("tailoring-file"):
            logger.error("Tailoring-file is not set")
            event.fail("Tailoring-file is not set")
            self.unit.status = ops.BlockedStatus("Cannot run hardening. Please configure a tailoring-file")
            return

        self._stored.audit_status = False
        try:
            self.unit.status = ops.MaintenanceStatus("Executing audit...")
            output = self.audit(xml_results_file=AUDIT_XML_RESULTS_PATH, html_results_file=AUDIT_HTML_RESULTS_PATH)
            logger.debug(output)
            results = {
                'result': "Audit completed",
                "xml-file": AUDIT_XML_RESULTS_PATH,
                "html-file": AUDIT_HTML_RESULTS_PATH,
            }
            event.set_results(results)
            last_audit_result = f"{self.parse_audit_results(AUDIT_XML_RESULTS_PATH)}%"

            # Update stored audit information
            self._stored.audit_status = True
            self._stored.last_audit_timestamp = datetime.now().isoformat()
            self._stored.last_audit_files = [AUDIT_XML_RESULTS_PATH, AUDIT_HTML_RESULTS_PATH]
            self._stored.last_audit_result = last_audit_result

            logger.debug(f"Audit finished. Results {results}")
            self.unit.status = ops.ActiveStatus(f"Audit finished. Result file: {AUDIT_HTML_RESULTS_PATH}")
        except Exception as e:
            self.unit.status = ops.BlockedStatus("Audit failed. Check juju-debug-log")
            logger.error(f"Audit failed: {str(e)}")

    def audit(self, html_results_file, xml_results_file):
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as fh:
                tailoring_content = base64.b64decode(
                    self.model.config["tailoring-file"]
                ).decode("utf-8")
                fh.write(tailoring_content)
                fh.flush()
                cmd = ["usg", "audit", "--tailoring-file", fh.name, "--results-file", xml_results_file, "--html-file", html_results_file]
                return subprocess.check_output(cmd, text=True)
        except Exception as e:
            logger.error(f"Audit failed: {str(e)}")
            raise

    def execute_pre_hardening_script(self):
        """
        Execute bash commands from pre-hardening-script config
        Bash commands need to be run in some cases, before the hardening, in order to remediate some rules
        """
        if not self.is_configuration_set("pre-hardening-script"):
            return False
        bash_content = self.model.config.get("pre-hardening-script", "")
        self.unit.status = ops.MaintenanceStatus("Executing pre-hardening script")
        try:
            # Using subprocess.run to be able to log stdout and stderr
            result = subprocess.run(
                bash_content, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                shell=True, executable="/bin/bash", text=True
            )

            if result.stdout:
                logger.info(f"Pre-hardening script output: {result.stdout}")
            if result.stderr:
                logger.error(f"Pre-hardening script error output: {result.stderr}")

            if result.returncode == 0:
                logger.info("Pre-hardening script executed successfully.")
            else:
                self.unit.status = ops.BlockedStatus(f"Pre-hardening script failed with code {result.returncode}. Check juju debug-log")
                logger.error(f"Pre-hardening script failed with code {result.returncode}")
                logger.error(result.stderr)
            return result.returncode

        except subprocess.SubprocessError as e:
            logger.error(f"An error occurred while executing the pre-hardening script: {e}")
            self.unit.status = ops.BlockedStatus("Pre-hardening script failed due to an exception. Check juju debug-log")
            return 1

    def cis_harden(self):
        tailoring_file = self.model.config.get("tailoring-file", "")
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as fh:
                tailoring_content = base64.b64decode(tailoring_file).decode("utf-8")
                fh.write(tailoring_content)
                fh.flush()
                cmd = ["usg", "fix", "--tailoring-file", fh.name]
                return subprocess.check_output(cmd, text=True)
        except Exception as e:
            logger.error(f"Hardening failed: {str(e)}")
            raise

    def _on_hardening_action(self, event):
        if not self.is_configuration_set("tailoring-file"):
            logger.error("Tailoring-file is not set")
            event.fail("Tailoring-file is not set")
            self.unit.status = ops.BlockedStatus("Cannot run hardening. Please configure a tailoring-file")
            return

        return_code = self.execute_pre_hardening_script()
        if return_code:
            event.fail("Failed to run pre-hardening script. Check juju debug-log")
            return

        self.unit.status = ops.MaintenanceStatus("Executing hardening...")
        self._stored.hardening_status = False
        self._stored.audit_status = False

        try:
            output = self.cis_harden()
            if output:
                event.fail("Failed to run CIS hardening. Check juju-debug-log")
                self.unit.status = ops.BlockedStatus("Failed to run CIS hardening. Check juju-debug-log")
            filename = None
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as fh:
                fh.write(output)
                filename = fh.name
            event.set_results({
                "result": "Complete! Please reboot the unit",
                "file": filename
            })
            self.unit.status = ops.BlockedStatus(
                "Hardening complete. Please reboot the unit"
            )
            self._stored.hardening_status = True

            # Update stored audit information
            self._stored.last_hardening_timestamp = datetime.now().isoformat()

        except Exception as e:
            logger.error(f"Hardening action failed: {str(e)}")
            event.fail("Hardening failed. Check juju debug-log")
            self.unit.status = ops.BlockedStatus("Hardening failed. Check juju debug-log")

    def _on_get_status_action(self, event):
        self.unit.status = ops.MaintenanceStatus("Fetching status...")

        try:
            output = {
                "hardened": self._stored.hardening_status,
                "last-harden-time": self._stored.last_hardening_timestamp,
                'audited': self._stored.audit_status,
                "last-audit-time": self._stored.last_audit_timestamp,
                "last-audit-result": self._stored.last_audit_result,
                "last-audit-files": self._stored.last_audit_files,
            }
            event.set_results({
                "result": output
            })
            self.check_state()

        except Exception as e:
            logger.error(f"Get status action failed: {str(e)}")
            event.fail("Get status failed. Check juju debug-log")
            self.unit.status = ops.BlockedStatus("Get status failed. Check juju debug-log")

    def _on_get_results_action(self, event):
        self.unit.status = ops.MaintenanceStatus("Fetching results...")

        if not self._stored.audit_status:
            msg = "No result found. Unit hardened but not audited. Run audit action first"
            logger.error(msg)
            event.fail(msg)
            return
        elif len(self._stored.last_audit_files) == 0:
            msg = "No result found. Unit hardened aud audited but audit files cannot be found. As result files are stored on /tmp, ensure the unit was not rebooted. Otherwise re-run audit action"
            logger.error(msg)
            event.fail(msg)

        try:
            format_param = event.params.get("format", "").lower()
            if format_param not in ["xml", "html"]:
                msg = "Invalid format parameter. Must be 'xml' or 'html'"
                logger.error(msg)
                event.fail(msg)
                return

            # Determine which file to read based on format
            file_path = AUDIT_XML_RESULTS_PATH if format_param == "xml" else AUDIT_HTML_RESULTS_PATH

            # # Check if file exists
            if not (file_path in self._stored.last_audit_files):
                msg = f"No {format_param} result file found in local storage"
                logger.error(msg)
                event.fail(msg)
                return

            # Read and return file content
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                    content_bytes = content.encode('utf-8')
                    encoded_content = base64.b64encode(content_bytes).decode('utf-8')
                    # Using print instead of event because output file is too large for the action buffer to handle
                    print(encoded_content)
                    # event.set_results({
                    #     "result": encoded_content
                    # })
                self.check_state()
            except IOError as e:
                msg = f"Failed to read {format_param} result file {file_path}: {str(e)}"
                logger.error(msg)
                event.fail(msg)
                self.unit.status = ops.BlockedStatus("Get results failed. Check juju debug-log")
                return

        except Exception as e:
            logger.error(f"Get results failed: {str(e)}")
            event.fail("Get results failed. Check juju debug-log")
            self.unit.status = ops.BlockedStatus("Get results failed. Check juju debug-log")


if __name__ == "__main__":
    ops.main(CharmCisHardeningCharm)
