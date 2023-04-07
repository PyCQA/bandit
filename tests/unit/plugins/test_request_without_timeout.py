# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class RequestWithoutTimeoutTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B113"])

    def test_requests_get_default(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.get('https://example.com')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_get_with_timeout_none(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.get('https://example.com', timeout=None)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_get_with_timeout(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.get('https://example.com', timeout=5)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_requests_post_default(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.post('https://example.com')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_post_with_timeout_none(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.post('https://example.com', timeout=None)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_post_with_timeout(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.post('https://example.com', timeout=5)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_requests_put_default(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.put('https://example.com')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_put_with_timeout_none(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.put('https://example.com', timeout=None)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_put_with_timeout(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.put('https://example.com', timeout=5)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_requests_delete_default(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.delete('https://example.com')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_delete_with_timeout_none(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.delete('https://example.com', timeout=None)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_delete_with_timeout(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.delete('https://example.com', timeout=5)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_requests_patch_default(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.patch('https://example.com')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_patch_with_timeout_none(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.patch('https://example.com', timeout=None)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_patch_with_timeout(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.patch('https://example.com', timeout=5)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_requests_options_default(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.options('https://example.com')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_options_with_timeout_none(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.options('https://example.com', timeout=None)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_options_with_timeout(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.options('https://example.com', timeout=5)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_requests_head_default(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.head('https://example.com')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_head_with_timeout_none(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.head('https://example.com', timeout=None)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.UNCONTROLLED_RESOURCE_CONSUMPTION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_head_with_timeout(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.head('https://example.com', timeout=5)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
