import hashlib

hashlib.new('md5')

hashlib.new('md4', b'test')

hashlib.new(name='md5', data=b'test')

hashlib.new('MD4', data=b'test')

hashlib.new('sha1')

hashlib.new('sha1', data=b'test')

hashlib.new('sha', data=b'test')

hashlib.new(name='SHA', data=b'test')

# usedforsecurity arg only availabe in Python 3.9+
hashlib.new('sha1', usedforsecurity=True)

# Test that plugin does not flag valid hash functions.
hashlib.new('sha256')

hashlib.new('SHA512')

# usedforsecurity arg only availabe in Python 3.9+
hashlib.new(name='sha1', usedforsecurity=False)
