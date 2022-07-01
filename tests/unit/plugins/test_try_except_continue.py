# SPDX-License-Identifier: Apache-2.0
import sys
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class TryExceptContinueTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B112"])

    def test_try_except_continue(self):
        fdata = textwrap.dedent(
            """
            try:
                a = 1
            except:
                continue
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.IMPROPER_CHECK_OF_EXCEPT_COND, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([4, 5], issue.linerange)
        else:
            self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_try_except_exception_continue(self):
        fdata = textwrap.dedent(
            """
            try:
                a = 1
            except Exception:
                continue
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.IMPROPER_CHECK_OF_EXCEPT_COND, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([4, 5], issue.linerange)
        else:
            self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_try_multi_except_pass(self):
        fdata = textwrap.dedent(
            """
            try:
                a = 1
            except ZeroDivisionError:
                a = 2
            except Exception:
                continue
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.IMPROPER_CHECK_OF_EXCEPT_COND, issue.cwe.id
        )
        self.assertEqual(6, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([6, 7], issue.linerange)
        else:
            self.assertEqual([6], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_try_except_continue_check_typed_exception_false(self):
        fdata = textwrap.dedent(
            """
            try:
                a = 1
            except ZeroDivisionError:
                continue
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_try_except_continue_check_typed_exception_true(self):
        test = next(
            x
            for x in self.b_manager.b_ts.tests["ExceptHandler"]
            if x.__name__ == "try_except_continue"
        )
        test._config = {"check_typed_exception": True}

        fdata = textwrap.dedent(
            """
            try:
                a = 1
            except ZeroDivisionError:
                continue
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.IMPROPER_CHECK_OF_EXCEPT_COND, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([4, 5], issue.linerange)
        else:
            self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_try_except_no_continue(self):
        fdata = textwrap.dedent(
            """
            try:
                a = 1
            except:
                a = 2
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_try_except_silly(self):
        fdata = textwrap.dedent(
            """
            try:
                a = 1
            except:
                continue
                a = 2
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
