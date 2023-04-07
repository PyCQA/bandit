# SPDX-License-Identifier: Apache-2.0
import textwrap

from tests.unit.blacklists import base_test_case


class PycryptodomeImportTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B414"])

    def test_import_cryptodome(self):
        fdata = textwrap.dedent(
            """
            from Cryptodome.Cipher import AES
            from Cryptodome import Random

            from . import CryptoMaterialsCacheEntry

            def test_pycrypto():
                key = b'Sixteen byte key'
                iv = Random.new().read(AES.block_size)
                cipher = pycrypto_arc2.new(key, AES.MODE_CFB, iv)
                factory = CryptoMaterialsCacheEntry()
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
