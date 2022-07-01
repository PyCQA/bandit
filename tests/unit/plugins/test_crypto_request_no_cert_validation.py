# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class CryptoRequestNoCertValidationTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B501"])

    def test_requests_get_verify_true(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.get('https://example.com', timeout=30, verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_requests_get_verify_false(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.get('https://example.com', timeout=30, verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_post_verify_true(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.post('https://example.com', timeout=30, verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_requests_post_verify_false(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.post('https://example.com', timeout=30, verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_put_verify_true(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.put('https://example.com', timeout=30, verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_requests_put_verify_false(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.put('https://example.com', timeout=30, verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_delete_verify_true(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.delete('https://example.com', timeout=30, verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_requests_delete_verify_false(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.delete('https://example.com', timeout=30, verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_patch_verify_true(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.patch('https://example.com', timeout=30, verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_requests_patch_verify_false(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.patch('https://example.com', timeout=30, verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_options_verify_true(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.options('https://example.com', timeout=30, verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_requests_options_verify_false(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.options('https://example.com', timeout=30, verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_requests_head_verify_true(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.head('https://example.com', timeout=30, verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_requests_head_verify_false(self):
        fdata = textwrap.dedent(
            """
            import requests
            requests.head('https://example.com', timeout=30, verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_httpx_request_verify_true(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.request('GET', 'https://example.com', verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_httpx_request_verify_false(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.request('GET', 'https://example.com', verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_httpx_get_verify_true(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.get('https://example.com', verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_httpx_get_verify_false(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.get('https://example.com', verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_httpx_options_verify_true(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.options('https://example.com', verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_httpx_options_verify_false(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.options('https://example.com', verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_httpx_head_verify_true(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.head('https://example.com', verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_httpx_head_verify_false(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.head('https://example.com', verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_httpx_post_verify_true(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.post('https://example.com', verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_httpx_post_verify_false(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.post('https://example.com', verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_httpx_put_verify_true(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.put('https://example.com', verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_httpx_put_verify_false(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.put('https://example.com', verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_httpx_patch_verify_true(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.patch('https://example.com', verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_httpx_patch_verify_false(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.patch('https://example.com', verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_httpx_delete_verify_true(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.delete('https://example.com', verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_httpx_delete_verify_false(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.delete('https://example.com', verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_httpx_stream_verify_true(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.stream('https://example.com', verify=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_httpx_stream_verify_false(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.stream('https://example.com', verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_httpx_client_default(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.Client()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_httpx_client_verify_false(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.Client(verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_httpx_asyncclient_default(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.AsyncClient()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_httpx_asyncclient_verify_false(self):
        fdata = textwrap.dedent(
            """
            import httpx
            httpx.AsyncClient(verify=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.IMPROPER_CERT_VALIDATION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)
