# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class YamlLoadTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B506"])

    def test_load_with_default_loader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}")
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_INPUT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_load_with_safeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}", Loader=yaml.SafeLoader)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_load_with_csafeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}", Loader=yaml.CSafeLoader)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_load_with_unsafe_loader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}", Loader=yaml.Loader)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_INPUT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_safe_load(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.safe_load("{}")
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_load_no_import(self):
        fdata = 'yaml.load("{}")'
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_load_safeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            from yaml import SafeLoader
            yaml.load("{}", SafeLoader)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_load_yaml_safeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}", yaml.SafeLoader)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_load_csafeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            from yaml import CSafeLoader
            yaml.load("{}", CSafeLoader)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_load_yaml_csafeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}", yaml.CSafeLoader)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
