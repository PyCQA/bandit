# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class FlaskDebugTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B201"])

    def test_app_run_debug_true(self):
        fdata = textwrap.dedent(
            """
            from flask import Flask
            app = Flask(__name__)
            app.run(debug=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.CODE_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_app_run_debug_false(self):
        fdata = textwrap.dedent(
            """
            from flask import Flask
            app = Flask(__name__)
            app.run(debug=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_app_run(self):
        fdata = textwrap.dedent(
            """
            from flask import Flask
            app = Flask(__name__)
            app.run()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_app_run_no_import(self):
        fdata = textwrap.dedent(
            """
            app = Flask(__name__)
            app.run(debug=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_unrelated_run(self):
        fdata = textwrap.dedent(
            """
            from flask import Flask
            run(debug=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
