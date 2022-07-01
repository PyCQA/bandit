# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class SshNoHostKeyVerificationTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B507"])

    def test_reject_policy(self):
        fdata = textwrap.dedent(
            """
            from paramiko import client
            ssh_client = client.SSHClient()
            ssh_client.set_missing_host_key_policy(client.RejectPolicy)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_auto_add_policy(self):
        fdata = textwrap.dedent(
            """
            from paramiko import client
            ssh_client = client.SSHClient()
            ssh_client.set_missing_host_key_policy(client.AutoAddPolicy)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_warning_policy(self):
        fdata = textwrap.dedent(
            """
            from paramiko import client
            ssh_client = client.SSHClient()
            ssh_client.set_missing_host_key_policy(client.WarningPolicy)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)
