# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class GeneralBadFilePermissionsTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B103"])

    def test_chmod_octal_227(self):
        fdata = textwrap.dedent(
            """
            import os
            os.chmod('/etc/passwd', 0o227)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_chmod_octal_7(self):
        fdata = textwrap.dedent(
            """
            import os
            os.chmod('/etc/passwd', 0o7)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_chmod_octal_664(self):
        fdata = textwrap.dedent(
            """
            import os
            os.chmod('/etc/passwd', 0o664)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_chmod_octal_777(self):
        fdata = textwrap.dedent(
            """
            import os
            os.chmod('/etc/passwd', 0o777)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_chmod_octal_770(self):
        fdata = textwrap.dedent(
            """
            import os
            os.chmod('/etc/passwd', 0o770)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_chmod_octal_776(self):
        fdata = textwrap.dedent(
            """
            import os
            os.chmod('/etc/passwd', 0o776)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_chmod_octal_760(self):
        fdata = textwrap.dedent(
            """
            import os
            os.chmod('/etc/passwd', 0o760)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_chmod_decimal_511(self):
        fdata = textwrap.dedent(
            """
            import os
            os.chmod('~/.bashrc', 511)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_chmod_hex_1ff(self):
        fdata = textwrap.dedent(
            """
            import os
            os.chmod('/tmp/oh_hai', 0x1ff)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_chmod_stat_s_irwxu(self):
        fdata = textwrap.dedent(
            """
            import os
            os.chmod('/etc/passwd', stat.S_IRWXU)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_chmod_file_as_arg(self):
        fdata = textwrap.dedent(
            """
            import os
            key_file = 'foo'
            os.chmod(key_file, 0o777)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)
