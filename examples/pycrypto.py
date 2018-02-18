from Crypto.Cipher import AES
from Crypto import Random

from . import CryptoMaterialsCacheEntry


def test_pycrypto():
    key = b'Sixteen byte key'
    iv = Random.new().read(AES.block_size)
    cipher = pycrypto_arc2.new(key, AES.MODE_CFB, iv)
    factory = CryptoMaterialsCacheEntry()
