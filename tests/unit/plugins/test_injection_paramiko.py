# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class InjectionParamikoTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B601"])

    def test_exec_command(self):
        fdata = textwrap.dedent(
            """
            import paramiko
            client = paramiko.client.SSHClient()
            client.exec_command('something; really; unsafe')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_exec_command_no_import(self):
        fdata = textwrap.dedent(
            """
            client = Client()
            client.exec_command('test')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
