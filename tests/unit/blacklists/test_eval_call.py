# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class EvalCallTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B307"])

    def test_eval_call(self):
        fdata = textwrap.dedent(
            """
            import os
            eval("os.getcwd()")
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B307", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_eval_method(self):
        fdata = textwrap.dedent(
            """
            class Test(object):
                def eval(self):
                    print("hi")
                def foo(self):
                    self.eval()

            Test().eval()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
