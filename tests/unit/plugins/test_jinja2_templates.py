# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class Jinja2TemplatesTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B701"])

    def test_environment_autoescape_false(self):
        fdata = textwrap.dedent(
            """
            import jinja2
            templateLoader = jinja2.FileSystemLoader(searchpath="/")
            jinja2.Environment(autoescape=False, loader=templateLoader)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.CODE_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_environment_autoescape_true(self):
        fdata = textwrap.dedent(
            """
            import jinja2
            templateLoader = jinja2.FileSystemLoader(searchpath="/")
            jinja2.Environment(autoescape=True, loader=templateLoader)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_environment_autoescape_select(self):
        fdata = textwrap.dedent(
            """
            import jinja2
            from jinja2 import Environment
            from jinja2 import select_autoescape
            templateLoader = jinja2.FileSystemLoader(searchpath="/")
            Environment(loader=templateLoader, autoescape=select_autoescape())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_environment_autoescape_func(self):
        fdata = textwrap.dedent(
            """
            import jinja2
            from jinja2 import Environment
            templateLoader = jinja2.FileSystemLoader(searchpath="/")
            def fake_func():
                return 'foobar'
            Environment(loader=templateLoader, autoescape=fake_func())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.CODE_INJECTION, issue.cwe.id)
        self.assertEqual(7, issue.lineno)
        self.assertEqual([7], issue.linerange)
        self.assertEqual(0, issue.col_offset)
