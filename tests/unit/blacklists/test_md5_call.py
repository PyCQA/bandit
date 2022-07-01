# SPDX-License-Identifier: Apache-2.0
import sys
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class Md5CallTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B303"])

    def test_hashlib_md5(self):
        fdata = textwrap.dedent(
            """
            import hashlib
            hashlib.md5(1)
            """
        )
        self.visitor.process(fdata)
        if sys.version_info >= (3, 9):
            self.assertEqual(0, len(self.visitor.tester.results))
        else:
            self.assertEqual(1, len(self.visitor.tester.results))
            issue = self.visitor.tester.results[0]
            self.assertEqual("B303", issue.test_id)
            self.assertEqual(bandit.MEDIUM, issue.severity)
            self.assertEqual(bandit.HIGH, issue.confidence)
            self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
            self.assertEqual(3, issue.lineno)
            self.assertEqual([3], issue.linerange)
            self.assertEqual(0, issue.col_offset)

    def test_hashlib_sha1(self):
        fdata = textwrap.dedent(
            """
            import hashlib
            hashlib.sha1(1)
            """
        )
        self.visitor.process(fdata)
        if sys.version_info >= (3, 9):
            self.assertEqual(0, len(self.visitor.tester.results))
        else:
            self.assertEqual(1, len(self.visitor.tester.results))
            issue = self.visitor.tester.results[0]
            self.assertEqual("B303", issue.test_id)
            self.assertEqual(bandit.MEDIUM, issue.severity)
            self.assertEqual(bandit.HIGH, issue.confidence)
            self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
            self.assertEqual(3, issue.lineno)
            self.assertEqual([3], issue.linerange)
            self.assertEqual(0, issue.col_offset)

    def test_crypto_hash_md2_new(self):
        fdata = textwrap.dedent(
            """
            from Crypto.Hash import MD2 as pycrypto_md2
            pycrypto_md2.new()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B303", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_crypto_hash_md4_new(self):
        fdata = textwrap.dedent(
            """
            from Crypto.Hash import MD4 as pycrypto_md4
            pycrypto_md4.new()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B303", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_crypto_hash_md5_new(self):
        fdata = textwrap.dedent(
            """
            from Crypto.Hash import MD5 as pycrypto_md5
            pycrypto_md5.new()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B303", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_crypto_hash_sha_new(self):
        fdata = textwrap.dedent(
            """
            from Crypto.Hash import SHA as pycrypto_sha
            pycrypto_sha.new()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B303", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptodome_hash_md2_new(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.Hash import MD2 as pycryptodomex_md2
            pycryptodomex_md2.new()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B303", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptodome_hash_md4_new(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.Hash import MD4 as pycryptodomex_md4
            pycryptodomex_md4.new()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B303", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptodome_hash_md5_new(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.Hash import MD5 as pycryptodomex_md5
            pycryptodomex_md5.new()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B303", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptodome_hash_sha_new(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.Hash import SHA as pycryptodomex_sha
            pycryptodomex_sha.new()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B303", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptography_hazmat_primitives_hashes_md5(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat.primitives import hashes
            hashes.MD5()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B303", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptography_hazmat_primitives_hashes_sha1(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat.primitives import hashes
            hashes.SHA1()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B303", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)
