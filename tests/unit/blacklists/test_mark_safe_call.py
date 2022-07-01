# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class MarkSafeTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B308"])

    def test_django_utils_safestring_mark_safe(self):
        fdata = textwrap.dedent(
            """
            from django.utils import safestring

            safestring.mark_safe('<b>Hello World</b>')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B308", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.XSS, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)
