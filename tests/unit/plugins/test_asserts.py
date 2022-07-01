# SPDX-License-Identifier: Apache-2.0
import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class AssertsTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B101"])

    def test_asserts(self):
        fdata = "assert True"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.IMPROPER_CHECK_OF_EXCEPT_COND, issue.cwe.id
        )
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(0, issue.col_offset)
