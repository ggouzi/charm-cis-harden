# Copyright 2024 pjds
# See LICENSE file for licensing details.

import unittest
from unittest.mock import patch
import subprocess
import base64

import ops
import ops.testing
from charm import CharmCisHardeningCharm


DUMP_TAILORING_FILE = """<?xml version='1.0' encoding='UTF-8'?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_scap-workbench_tailoring_default">
  <benchmark href="/usr/share/ubuntu-scap-security-guides/1/benchmarks/ssg-ubuntu2204-xccdf.xml"/>
  <version time="2024-10-24T19:35:23">1</version>
  <Profile id="xccdf_org.ssgproject.content_profile_cis_level2_server_customized" extends="xccdf_org.ssgproject.content_profile_cis_level2_server">
    <title xmlns:xhtml="http://www.w3.org/1999/xhtml" xml:lang="en-US" override="true">CIS Ubuntu 22.04 Level 2 Server Benchmark [CUSTOMIZED]</title>
    <description xmlns:xhtml="http://www.w3.org/1999/xhtml" xml:lang="en-US" override="true">This baseline aligns to the Center for Internet Security Ubuntu 22.04 LTS Benchmark, v1.0.0, released 08-30-2022.</description>
    <!--1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Automated)-->
    <select idref="xccdf_org.ssgproject.content_rule_kernel_module_cramfs_disabled" selected="true"/>
    <!--4.1.3.19 Ensure kernel module loading and unloading is collected (Automated)-->
    <select idref="xccdf_org.ssgproject.content_rule_audit_rules_kernel_module_loading_init" selected="true"/>
    <select idref="xccdf_org.ssgproject.content_rule_audit_rules_kernel_module_loading_delete" selected="true"/>
    <select idref="xccdf_org.ssgproject.content_rule_audit_rules_privileged_commands_modprobe" selected="true"/>
    <select idref="xccdf_org.ssgproject.content_rule_audit_rules_privileged_commands_insmod" selected="true"/>
    <select idref="xccdf_org.ssgproject.content_rule_audit_rules_privileged_commands_rmmod" selected="true"/>
  </Profile>
</Tailoring>
"""

class TestCharmCisHardening(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(CharmCisHardeningCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.test_tailoring = base64.b64encode(bytes(DUMP_TAILORING_FILE, "UTF-8")).decode('utf-8')

    def test_config_changed_valid(self):
        """Test that a valid tailoring file is accepted."""
        self.harness.update_config({"tailoring-file": self.test_tailoring})
        self.assertEqual(
            base64.b64decode(self.harness.model.config["tailoring-file"]).decode('utf-8'),
            DUMP_TAILORING_FILE
        )

    def test_config_changed_invalid_base64(self):
        with self.assertRaises(Exception):
            # This should fail as it's not valid base64
            self.harness.update_config({"tailoring-file": "not-base64-content"})
            self.harness.charm.cis_harden()

    @patch('charmhelpers.fetch.apt_update')
    @patch('charmhelpers.fetch.apt_install')
    def test_install_default(self, mock_apt_install, mock_apt_update):
        self.harness.update_config({
            "auto-harden": False,
            "tailoring-file": self.test_tailoring
        })
        self.harness.charm.on.install.emit()
        mock_apt_update.assert_called_once()
        mock_apt_install.assert_called_once_with(['usg'], fatal=True)
        self.assertIsInstance(self.harness.model.unit.status, ops.BlockedStatus)
        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("Ready for CIS hardening. Run 'execute-cis' action")
        )

    @patch('charmhelpers.fetch.apt_update')
    @patch('charmhelpers.fetch.apt_install')
    @patch('subprocess.check_output')
    def test_install_with_auto_harden(self, mock_check_output, mock_apt_install, mock_apt_update):
        self.harness.update_config({
            "auto-harden": True,
            "tailoring-file": self.test_tailoring
        })
        mock_check_output.return_value = "Hardening complete"
        self.harness.charm.on.install.emit()
        mock_apt_update.assert_called()
        mock_apt_install.assert_called_with(['usg'], fatal=True)
        mock_check_output.assert_called()
        self.assertTrue(mock_check_output.call_args[0][0][0:2] == ['usg', 'fix'])


    @patch('subprocess.check_output')
    def test_execute_audit_action(self, mock_check_output):
        """Test the execute-audit action."""
        expected_output = "Audit results"
        mock_check_output.return_value = expected_output.encode('utf-8')
        action_event = self.harness.run_action("execute-audit")
        self.harness.charm._on_audit_action(action_event)
        mock_check_output.assert_called_with(
            "usg audit --tailoring-file /tmp/audit.results".split(" ")
        )
        self.assertEqual(action_event.results["result"], expected_output)
        self.assertEqual(action_event.results["file"], "/tmp/audit.results")

    @patch('subprocess.check_output')
    def test_start_hardened(self, mock_check_output):
        mock_check_output.return_value = b"sysctl output"
        self.harness.charm._stored.hardening_status = True
        self.harness.charm.on.start.emit()
        mock_check_output.assert_called_once_with("sysctl --system".split(" "))
        self.assertIsInstance(self.harness.model.unit.status, ops.ActiveStatus)
        self.assertEqual(
            self.harness.model.unit.status,
            ops.ActiveStatus("Unit is hardened. Use 'execute-audit' action to check compliance")
        )

    @patch('subprocess.check_output')
    def test_start_not_hardened(self, mock_check_output):
        mock_check_output.return_value = b"sysctl output"
        self.harness.charm._stored.hardening_status = False
        self.harness.charm.on.start.emit()
        mock_check_output.assert_called_once_with("sysctl --system".split(" "))
        self.assertIsInstance(self.harness.model.unit.status, ops.BlockedStatus)
        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("Ready for CIS hardening. Run 'execute-cis' action")
        )

    def test_install_failure(self):
        with patch('charmhelpers.fetch.apt_update', side_effect=Exception("Update failed")):
            self.harness.charm.on.install.emit()
            self.assertIsInstance(self.harness.model.unit.status, ops.BlockedStatus)
            self.assertEqual(
                self.harness.model.unit.status,
                ops.BlockedStatus("Install failed: Update failed")
            )


if __name__ == '__main__':
    unittest.main()
