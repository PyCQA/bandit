# SPDX-License-Identifier: Apache-2.0
import sys
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class GeneralHardcodedPasswordTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B105", "B106", "B107"])

    def test_class_attribute(self):
        fdata = textwrap.dedent(
            """
            class SomeClass:
                password = "class_password"
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B105", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(15, issue.col_offset)

    def test_function_kwarg(self):
        fdata = textwrap.dedent(
            """
            def someFunction(user, password="Admin"):
                print("Hi " + user)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B107", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([2, 3], issue.linerange)
        else:
            self.assertEqual([2], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_function_password_eq_root(self):
        fdata = textwrap.dedent(
            """
            def someFunction2(password):
                if password == "root":
                    print("OK, logged in")
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B105", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(19, issue.col_offset)

    def test_function_password_eq_empty(self):
        fdata = textwrap.dedent(
            """
            def noMatch(password):
                if password == '':
                    print("No password!")
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B105", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(19, issue.col_offset)

    def test_function_password_eq_ajklawejrkl42348swfgkg(self):
        fdata = textwrap.dedent(
            """
            def NoMatch2(password):
                if password == "ajklawejrkl42348swfgkg":
                    print("Nice password!")
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B105", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(19, issue.col_offset)

    def test_function_obj_password_eq(self):
        fdata = textwrap.dedent(
            """
            def noMatchObject():
                obj = SomeClass()
                if obj.password == "this cool password":
                    print(obj.password)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B105", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(23, issue.col_offset)

    def test_function_kwarg2(self):
        fdata = textwrap.dedent(
            """
            def doLogin(password="blerg"):
                pass
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B107", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([2, 3], issue.linerange)
        else:
            self.assertEqual([2], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_function_no_password(self):
        fdata = textwrap.dedent(
            """
            def NoMatch3(a, b):
                pass
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_call_kwarg(self):
        fdata = 'doLogin(password="blerg")'
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B106", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_password_blerg(self):
        fdata = 'password = "blerg"'
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B105", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(11, issue.col_offset)

    def test_dict_password_blerg(self):
        fdata = 'd["password"] = "blerg"'
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B105", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(2, issue.col_offset)

    def test_email_password_secret(self):
        fdata = 'EMAIL_PASSWORD = "secret"'
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B105", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(17, issue.col_offset)

    def test_email_pwd_emails_secret(self):
        fdata = "email_pwd = 'emails_secret'"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B105", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(12, issue.col_offset)

    def test_my_secret_password_for_email(self):
        fdata = "my_secret_password_for_email = 'd6s$f9g!j8mg7hw?n&2'"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B105", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(31, issue.col_offset)

    def test_passphrase_1234(self):
        fdata = "passphrase='1234'"
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B105", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.HARD_CODED_PASSWORD, issue.cwe.id)
        self.assertEqual(1, issue.lineno)
        self.assertEqual([1], issue.linerange)
        self.assertEqual(11, issue.col_offset)
