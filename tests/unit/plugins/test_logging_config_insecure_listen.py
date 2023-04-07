# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class LoggingConfigListenTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B612"])

    def test_logging_config_listen(self):
        fdata = textwrap.dedent(
            """
            from logging import config
            server = config.listen(9999)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.CODE_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(9, issue.col_offset)

    def test_logging_config_listen_verify(self):
        fdata = textwrap.dedent(
            """
            from logging import config
            server = config.listen(9999, verify=lambda x: x)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
