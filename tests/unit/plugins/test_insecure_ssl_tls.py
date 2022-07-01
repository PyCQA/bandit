# SPDX-License-Identifier: Apache-2.0
import sys
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class InsecureSslTlsTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B502", "B503", "B504"])

    def test_ssl_wrap_socket_ssl_v2(self):
        fdata = textwrap.dedent(
            """
            import ssl
            ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv2)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_ssl_wrap_socket_ssl_v3(self):
        fdata = textwrap.dedent(
            """
            import ssl
            ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv3)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_ssl_wrap_socket_tls_v1(self):
        fdata = textwrap.dedent(
            """
            import ssl
            ssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_ssl_wrap_socket(self):
        fdata = textwrap.dedent(
            """
            import ssl
            ssl.wrap_socket()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B504", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_call_protocol_ssl_v2(self):
        fdata = textwrap.dedent(
            """
            import ssl
            herp_derp(ssl_version=ssl.PROTOCOL_SSLv2)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_call_protocol_ssl_v3(self):
        fdata = textwrap.dedent(
            """
            import ssl
            herp_derp(ssl_version=ssl.PROTOCOL_SSLv3)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_call_protocol_tls_v1(self):
        fdata = textwrap.dedent(
            """
            import ssl
            herp_derp(ssl_version=ssl.PROTOCOL_TLSv1)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_func_protocol_ssl_v2(self):
        fdata = textwrap.dedent(
            """
            import ssl
            def open_ssl_socket(version=ssl.PROTOCOL_SSLv2):
                pass
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B503", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([3, 4], issue.linerange)
        else:
            self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pyopenssl_ssl_v2(self):
        fdata = textwrap.dedent(
            """
            from pyOpenSSL import SSL
            SSL.Context(method=SSL.SSLv2_METHOD)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pyopenssl_ssl_v23(self):
        fdata = textwrap.dedent(
            """
            from pyOpenSSL import SSL
            SSL.Context(method=SSL.SSLv23_METHOD)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pyopenssl_ssl_v3(self):
        fdata = textwrap.dedent(
            """
            from pyOpenSSL import SSL
            SSL.Context(method=SSL.SSLv3_METHOD)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pyopenssl_tls_v1(self):
        fdata = textwrap.dedent(
            """
            from pyOpenSSL import SSL
            SSL.Context(method=SSL.TLSv1_METHOD)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_call_pyopenssl_ssl_v2(self):
        fdata = textwrap.dedent(
            """
            from pyOpenSSL import SSL
            herp_derp(method=SSL.SSLv2_METHOD)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_call_pyopenssl_ssl_v23(self):
        fdata = textwrap.dedent(
            """
            from pyOpenSSL import SSL
            herp_derp(method=SSL.SSLv23_METHOD)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_call_pyopenssl_ssl_v3(self):
        fdata = textwrap.dedent(
            """
            from pyOpenSSL import SSL
            herp_derp(method=SSL.SSLv3_METHOD)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_call_pyopenssl_tls_v1(self):
        fdata = textwrap.dedent(
            """
            from pyOpenSSL import SSL
            herp_derp(method=SSL.TLSv1_METHOD)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B502", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_func_pyopenssl_ssl_v2(self):
        fdata = textwrap.dedent(
            """
            from pyOpenSSL import SSL
            def open_ssl_socket(version=SSL.SSLv2_METHOD):
                pass
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B503", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([3, 4], issue.linerange)
        else:
            self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_func_pyopenssl_ssl_v23(self):
        fdata = textwrap.dedent(
            """
            from pyOpenSSL import SSL
            def open_ssl_socket(version=SSL.SSLv23_METHOD):
                pass
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B503", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([3, 4], issue.linerange)
        else:
            self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_func_pyopenssl_tls_v11(self):
        fdata = textwrap.dedent(
            """
            from pyOpenSSL import SSL
            def open_ssl_socket(version=SSL.TLSv1_1_METHOD):
                pass
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
