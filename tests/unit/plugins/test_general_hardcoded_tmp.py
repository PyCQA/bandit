# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class GeneralHardcodedTmpTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B108"])

    def test_tmp(self):
        fdata = textwrap.dedent(
            """
            with open('/tmp/abc', 'w') as f:
                f.write('def')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.INSECURE_TEMP_FILE, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        self.assertEqual([2], issue.linerange)
        self.assertEqual(10, issue.col_offset)

    def test_var_tmp(self):
        fdata = textwrap.dedent(
            """
            with open('/var/tmp/123', 'w') as f:
                f.write('def')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.INSECURE_TEMP_FILE, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        self.assertEqual([2], issue.linerange)
        self.assertEqual(10, issue.col_offset)

    def test_dev_shm(self):
        fdata = textwrap.dedent(
            """
            with open('/dev/shm/unit/test', 'w') as f:
                f.write('def')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.INSECURE_TEMP_FILE, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        self.assertEqual([2], issue.linerange)
        self.assertEqual(10, issue.col_offset)

    def test_abc_tmp(self):
        fdata = textwrap.dedent(
            """
            with open('/abc/tmp', 'w') as f:
                f.write('def')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_foo_bar(self):
        fdata = textwrap.dedent(
            """
            with open('/foo/bar', 'w') as f:
                f.write('def')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
