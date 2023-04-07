# SPDX-License-Identifier: Apache-2.0
import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class TelnetlibImportTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B401"])

    def test_import_telnetlib(self):
        fdata = "import telnetlib"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B401", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.CLEARTEXT_TRANSMISSION, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(0, issue.col_offset)
