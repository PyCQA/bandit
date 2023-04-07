# SPDX-License-Identifier: Apache-2.0
import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class PicklemportTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B403"])

    def test_import_pickle(self):
        fdata = "import pickle"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B403", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_import_dill(self):
        fdata = "import dill"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B403", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_import_shelve(self):
        fdata = "import shelve"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B403", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA, issue.cwe.id
        )
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(0, issue.col_offset)
