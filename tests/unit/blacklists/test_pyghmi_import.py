# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class PyghmiImportTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B415"])

    def test_import_pyghmi(self):
        fdata = textwrap.dedent(
            """
            from pyghmi.ipmi import command
            cmd = command.Command(
                bmc="bmc",
                userid="userid",
                password="ZjE4ZjI0NTE4YmI2NGJjZDliOGY3ZmJiY2UyN2IzODQK"
            )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B415", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.CLEARTEXT_TRANSMISSION, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        self.assertEqual([2], issue.linerange)
        self.assertEqual(0, issue.col_offset)
