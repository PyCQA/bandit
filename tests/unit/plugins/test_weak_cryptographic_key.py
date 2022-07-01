# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class WeakCryptographicKeyTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B505"])

    def test_cryptography_dsa_2048(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat import backends
            from cryptography.hazmat.primitives.asymmetric import dsa
            dsa.generate_private_key(key_size=2048,
                         backend=backends.default_backend())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_cryptography_ec_secp384r1(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat import backends
            from cryptography.hazmat.primitives.asymmetric import ec
            ec.generate_private_key(curve=ec.SECP384R1,
                                    backend=backends.default_backend())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_cryptography_rsa_2048(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat import backends
            from cryptography.hazmat.primitives.asymmetric import rsa
            rsa.generate_private_key(public_exponent=65537,
                                     key_size=2048,
                                     backend=backends.default_backend())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_pycrypto_dsa_2048(self):
        fdata = textwrap.dedent(
            """
            from Crypto.PublicKey import DSA as pycrypto_dsa
            pycrypto_dsa.generate(bits=2048)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_pycrypto_rsa_2048(self):
        fdata = textwrap.dedent(
            """
            from Crypto.PublicKey import RSA as pycrypto_rsa
            pycrypto_rsa.generate(bits=2048)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_pycryptodomex_dsa_2048(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.PublicKey import DSA as pycryptodomex_dsa
            pycryptodomex_dsa.generate(bits=2048)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_pycryptodomex_rsa_2048(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.PublicKey import RSA as pycryptodomex_rsa
            pycryptodomex_rsa.generate(bits=2048)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_cryptography_dsa_4096(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat import backends
            from cryptography.hazmat.primitives.asymmetric import dsa
            dsa.generate_private_key(4096,
                                     backends.default_backend())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_cryptography_ec_secp256k1(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat import backends
            from cryptography.hazmat.primitives.asymmetric import ec
            ec.generate_private_key(ec.SECP256K1,
                                    backends.default_backend())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_cryptography_rsa_4096(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat import backends
            from cryptography.hazmat.primitives.asymmetric import rsa
            rsa.generate_private_key(3,
                                     4096,
                                     backends.default_backend())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_pycrypto_dsa_4096(self):
        fdata = textwrap.dedent(
            """
            from Crypto.PublicKey import DSA as pycrypto_dsa
            pycrypto_dsa.generate(4096)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_pycrypto_rsa_4096(self):
        fdata = textwrap.dedent(
            """
            from Crypto.PublicKey import RSA as pycrypto_rsa
            pycrypto_rsa.generate(4096)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_pycryptodomex_dsa_4096(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.PublicKey import DSA as pycryptodomex_dsa
            pycryptodomex_dsa.generate(4096)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_pycryptodomex_rsa_4096(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.PublicKey import RSA as pycryptodomex_rsa
            pycryptodomex_rsa.generate(4096)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_cryptography_dsa_1024(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat import backends
            from cryptography.hazmat.primitives.asymmetric import dsa
            dsa.generate_private_key(key_size=1024,
                                     backend=backends.default_backend())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4, 5], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptography_ec_sect163r2(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat import backends
            from cryptography.hazmat.primitives.asymmetric import ec
            ec.generate_private_key(curve=ec.SECT163R2,
                                    backend=backends.default_backend())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4, 5], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptography_rsa_1024(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat import backends
            from cryptography.hazmat.primitives.asymmetric import rsa
            rsa.generate_private_key(public_exponent=65537,
                                     key_size=1024,
                                     backend=backends.default_backend())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4, 5, 6], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pycrypto_dsa_1024(self):
        fdata = textwrap.dedent(
            """
            from Crypto.PublicKey import DSA as pycrypto_dsa
            pycrypto_dsa.generate(bits=1024)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pycrypto_rsa_1024(self):
        fdata = textwrap.dedent(
            """
            from Crypto.PublicKey import RSA as pycrypto_rsa
            pycrypto_rsa.generate(bits=1024)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pycryptodomex_dsa_1024(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.PublicKey import DSA as pycryptodomex_dsa
            pycryptodomex_dsa.generate(bits=1024)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pycryptodomex_rsa_1024(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.PublicKey import RSA as pycryptodomex_rsa
            pycryptodomex_rsa.generate(bits=1024)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptography_dsa_512(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat import backends
            from cryptography.hazmat.primitives.asymmetric import dsa
            dsa.generate_private_key(512,
                                     backends.default_backend())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4, 5], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptography_rsa_512(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat import backends
            from cryptography.hazmat.primitives.asymmetric import rsa
            rsa.generate_private_key(3,
                                     512,
                                     backends.default_backend())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH, issue.cwe.id
        )
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4, 5, 6], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pycrypto_dsa_512(self):
        fdata = textwrap.dedent(
            """
            from Crypto.PublicKey import DSA as pycrypto_dsa
            pycrypto_dsa.generate(512)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pycrypto_rsa_512(self):
        fdata = textwrap.dedent(
            """
            from Crypto.PublicKey import RSA as pycrypto_rsa
            pycrypto_rsa.generate(512)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pycryptodomex_dsa_512(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.PublicKey import DSA as pycryptodomex_dsa
            pycryptodomex_dsa.generate(512)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pycryptodomex_rsa_512(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.PublicKey import RSA as pycryptodomex_rsa
            pycryptodomex_rsa.generate(512)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cryptography_ec_unknown_curve(self):
        fdata = textwrap.dedent(
            """
            from cryptography.hazmat import backends
            from cryptography.hazmat.primitives.asymmetric import ec
            ec.generate_private_key(
                curve=curves[self.curve]['create'](self.size),
                backend=backends.default_backend()
            )
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
