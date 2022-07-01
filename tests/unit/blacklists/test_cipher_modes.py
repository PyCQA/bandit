# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.blacklists import base_test_case


class CipherModesTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B305"])

    def test_cipher_mode_ecb(self):
        fdata = textwrap.dedent(
            """
            import os
            from cryptography.hazmat.primitives.ciphers.modes import ECB
            iv = os.urandom(16)
            ECB(iv)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B305", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.BROKEN_CRYPTO, issue.cwe.id)
        self.assertEqual(5, issue.lineno)
        self.assertEqual([5], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_cipher_mode_ctr(self):
        fdata = textwrap.dedent(
            """
            import os
            from cryptography.hazmat.primitives.ciphers import algorithms
            from cryptography.hazmat.primitives.ciphers import modes
            key = os.urandom(32)
            iv = os.urandom(16)
            algorithms.AES.new(key, modes.CTR, iv)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_cipher_mode_cbc(self):
        fdata = textwrap.dedent(
            """
            import os
            from cryptography.hazmat.primitives.ciphers.modes import CBC
            iv = os.urandom(16)
            CBC(iv)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
