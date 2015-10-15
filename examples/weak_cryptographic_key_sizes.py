from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA


# Correct
dsa.generate_private_key(key_size=2048,
                         backend=backends.default_backend())
rsa.generate_private_key(public_exponent=65537,
                         key_size=2048,
                         backend=backends.default_backend())
DSA.generate(bits=2048)
RSA.generate(bits=2048)

# Also correct: without keyword args
dsa.generate_private_key(4096,
                         backends.default_backend())
ec.generate_private_key(ec.SECP256K1,
                        backends.default_backend())
rsa.generate_private_key(3,
                         4096,
                         backends.default_backend())
DSA.generate(4096)
RSA.generate(4096)

# Incorrect: weak key sizes
dsa.generate_private_key(key_size=1024,
                         backend=backends.default_backend())
rsa.generate_private_key(public_exponent=65537,
                         key_size=1024,
                         backend=backends.default_backend())
DSA.generate(bits=1024)
RSA.generate(bits=1024)

# Also incorrect: without keyword args
dsa.generate_private_key(512,
                         backends.default_backend())
ec.generate_private_key(ec.SECT163R2,
                        backends.default_backend())
rsa.generate_private_key(3,
                         512,
                         backends.default_backend())
DSA.generate(512)
RSA.generate(512)
