# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class UnverifiedContextCallTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B323"])

    def test_create_unverified_context(self):
        fdata = textwrap.dedent(
            """
            import ssl
            ssl._create_unverified_context()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B323", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_create_default_context(self):
        fdata = textwrap.dedent(
            """
            import ssl
            ssl.create_default_context()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
