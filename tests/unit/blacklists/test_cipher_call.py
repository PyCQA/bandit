# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class CipherCallTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B304"])

    def test_crypto_cipher_arc2_new(self):
        fdata = textwrap.dedent(
            """
            from Crypto.Cipher import ARC2 as pycrypto_arc2
            from Crypto import Random
            key = b'Sixteen byte key'
            iv = Random.new().read(pycrypto_arc2.block_size)
            pycrypto_arc2.new(key, pycrypto_arc2.MODE_CFB, iv)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B304", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(6, issue.lineno)
        self.assertEqual([6], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_crypto_cipher_arc4_new(self):
        fdata = textwrap.dedent(
            """
            from Crypto.Cipher import ARC4 as pycrypto_arc4
            from Crypto import Random
            key = b'Very long and confidential key'
            nonce = Random.new().read(16)
            tempkey = SHA.new(key+nonce).digest()
            pycrypto_arc4.new(tempkey)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B304", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(7, issue.lineno)
        self.assertEqual([7], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_crypto_cipher_blowfish_new(self):
        fdata = textwrap.dedent(
            """
            from Crypto.Cipher import Blowfish as pycrypto_blowfish
            from Crypto import Random
            key = b'An arbitrarily long key'
            bs = pycrypto_blowfish.block_size
            iv = Random.new().read(bs)
            pycrypto_blowfish.new(key, pycrypto_blowfish.MODE_CBC, iv)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B304", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(7, issue.lineno)
        self.assertEqual([7], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_crypto_cipher_des_new(self):
        fdata = textwrap.dedent(
            """
            from Crypto.Cipher import DES as pycrypto_des
            from Crypto import Random
            nonce = Random.new().read(pycrypto_des.block_size / 2)
            ctr = Counter.new(pycrypto_des.block_size * 8 / 2, prefix=nonce)
            pycrypto_des.new(key, pycrypto_des.MODE_CTR, counter=ctr)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B304", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(6, issue.lineno)
        self.assertEqual([6], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_crypto_cipher_xor_new(self):
        fdata = textwrap.dedent(
            """
            from Crypto.Cipher import XOR as pycrypto_xor
            key = b'Super secret key'
            pycrypto_xor.new(key)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B304", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptodome_cipher_arc2_new(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.Cipher import ARC2 as pycryptodomex_arc2
            from Crypto import Random
            key = b'Sixteen byte key'
            iv = Random.new().read(pycryptodomex_arc2.block_size)
            pycryptodomex_arc2.new(key, pycryptodomex_arc2.MODE_CFB, iv)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B304", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(6, issue.lineno)
        self.assertEqual([6], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptodome_cipher_arc4_new(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.Cipher import ARC4 as pycryptodomex_arc4
            from Cryptodome import Random
            key = b'Very long and confidential key'
            nonce = Random.new().read(16)
            tempkey = SHA.new(key + nonce).digest()
            pycryptodomex_arc4.new(tempkey)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B304", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(7, issue.lineno)
        self.assertEqual([7], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptodome_cipher_blowfish_new(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.Cipher import Blowfish as pycryptodomex_blowfish
            from Cryptodome import Random
            key = b'An arbitrarily long key'
            bs = pycryptodomex_blowfish.block_size
            iv = Random.new().read(bs)
            mode = pycryptodomex_blowfish.MODE_CBC
            pycryptodomex_blowfish.new(key, mode, iv)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B304", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(8, issue.lineno)
        self.assertEqual([8], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptodome_cipher_des_new(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.Cipher import DES as pycryptodomex_des
            from Cryptodome import Random
            nonce = Random.new().read(pycryptodomex_des.block_size / 2)
            ctr = Counter.new(pycryptodomex_des.block_size * 8/2, prefix=nonce)
            pycryptodomex_des.new(key, pycryptodomex_des.MODE_CTR, counter=ctr)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B304", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(6, issue.lineno)
        self.assertEqual([6], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptodome_cipher_xor_new(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.Cipher import XOR as pycryptodomex_xor
            key = b'Super secret key'
            pycryptodomex_xor.new(key)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B304", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptography_ciphers_algorithms_arc4(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat.primitives.ciphers import Cipher
            from cryptography.hazmat.primitives.ciphers import algorithms
            from cryptography.hazmat.backends import default_backend
            key = b'Super secret key'
            Cipher(
                algorithms.ARC4(key),
                mode=None,
                backend=default_backend()
            )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B304", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(7, issue.lineno)
        self.assertEqual([7], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_cryptography_ciphers_algorithms_blowfish(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat.primitives.ciphers import Cipher
            from cryptography.hazmat.primitives.ciphers import algorithms
            from cryptography.hazmat.backends import default_backend
            key = b'Super secret key'
            Cipher(
                algorithms.Blowfish(key),
                mode=None,
                backend=default_backend()
            )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B304", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(7, issue.lineno)
        self.assertEqual([7], issue.linerange)
        self.assertEqual(4, issue.col_offset)

    def test_cryptography_ciphers_algorithms_idea(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat.primitives.ciphers import Cipher
            from cryptography.hazmat.primitives.ciphers import algorithms
            from cryptography.hazmat.backends import default_backend
            key = b'Super secret key'
            Cipher(
                algorithms.IDEA(key),
                mode=None,
                backend=default_backend(),
            )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B304", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(7, issue.lineno)
        self.assertEqual([7], issue.linerange)
        self.assertEqual(4, issue.col_offset)
