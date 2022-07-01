# SPDX-License-Identifier: Apache-2.0
import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class ExecTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B102"])

    def test_exec_used(self):
        fdata = "exec('do evil')"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(0, issue.col_offset)
