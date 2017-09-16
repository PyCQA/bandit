import hashlib

hashlib.new('md5')

hashlib.new('md4', 'test')

hashlib.new(name='md5', string='test')

hashlib.new('MD4', string='test')

hashlib.new(string='test', name='MD5')

# Test that plugin does not flag valid hash functions.
hashlib.new('sha256')

hashlib.new('SHA512')
