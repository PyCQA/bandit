# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class GeneralBindAllInterfacesTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B104"])

    def test_bind_all_interfaces(self):
        fdata = textwrap.dedent(
            """
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('0.0.0.0', 31137))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.MULTIPLE_BINDS, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(8, issue.col_offset)

    def test_bind_address(self):
        fdata = textwrap.dedent(
            """
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('192.168.0.1', 8080))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
