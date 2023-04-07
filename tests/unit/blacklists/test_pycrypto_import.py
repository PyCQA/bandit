# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class PycryptoImportTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B413"])

    def test_import_crypto_cipher(self):
        fdata = textwrap.dedent(
            """
            from Crypto.Cipher import AES
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B413", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        self.assertEqual([2], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_import_crypto_hash(self):
        fdata = textwrap.dedent(
            """
            from Crypto import Hash
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B413", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        self.assertEqual([2], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_import_crypto_io(self):
        fdata = textwrap.dedent(
            """
            from Crypto import IO
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B413", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        self.assertEqual([2], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_import_crypto_protocol(self):
        fdata = textwrap.dedent(
            """
            from Crypto import Protocol
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B413", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        self.assertEqual([2], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_import_crypto_publickey(self):
        fdata = textwrap.dedent(
            """
            from Crypto import PublicKey
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B413", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        self.assertEqual([2], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_import_crypto_random(self):
        fdata = textwrap.dedent(
            """
            from Crypto import Random
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B413", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        self.assertEqual([2], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_import_crypto_signature(self):
        fdata = textwrap.dedent(
            """
            from Crypto import Signature
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B413", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        self.assertEqual([2], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_import_crypto_util(self):
        fdata = textwrap.dedent(
            """
            from Crypto import Util
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B413", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(2, issue.lineno)
        self.assertEqual([2], issue.linerange)
        self.assertEqual(0, issue.col_offset)
