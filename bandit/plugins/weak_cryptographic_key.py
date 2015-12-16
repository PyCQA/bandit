# Copyright (c) 2015 VMware, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

r"""
Description
-----------
As computational power increases, so does the ability to break ciphers with
smaller key lengths. The recommended key length size is 2048 and higher. 1024
bits and below are now considered breakable. This plugin test checks for use
of any key less than 2048 bits and returns a high severity error if lower than
1024 and a medium severity error greater than 1024 but less than 2048.

Config Options
--------------
None

Sample Output
-------------
.. code-block:: none

    >> Issue: DSA key sizes below 1024 bits are considered breakable.
       Severity: High   Confidence: High
       Location: examples/weak_cryptographic_key_sizes.py:36
    35  # Also incorrect: without keyword args
    36  dsa.generate_private_key(512,
    37                           backends.default_backend())
    38  rsa.generate_private_key(3,

References
----------
 - http://csrc.nist.gov/publications/nistpubs/800-131A/sp800-131A.pdf
 - https://security.openstack.org/guidelines/dg_strong-crypto.html

.. versionadded:: 0.14.0

"""

import bandit
from bandit.core.test_properties import *


def _classify_key_size(key_type, key_size):
    key_sizes = {
        'DSA': [(1024, bandit.HIGH), (2048, bandit.MEDIUM)],
        'RSA': [(1024, bandit.HIGH), (2048, bandit.MEDIUM)],
        'EC': [(160, bandit.HIGH), (224, bandit.MEDIUM)],
    }

    for size, level in key_sizes[key_type]:
        if key_size < size:
            return bandit.Issue(
                severity=level,
                confidence=bandit.HIGH,
                text='%s key sizes below %d bits are considered breakable. ' %
                     (key_type, size))


def _weak_crypto_key_size_cryptography_io(context):
    func_key_type = {
        'cryptography.hazmat.primitives.asymmetric.dsa.'
        'generate_private_key': 'DSA',
        'cryptography.hazmat.primitives.asymmetric.rsa.'
        'generate_private_key': 'RSA',
        'cryptography.hazmat.primitives.asymmetric.ec.'
        'generate_private_key': 'EC',
    }
    arg_position = {
        'DSA': 0,
        'RSA': 1,
        'EC': 0,
    }
    key_type = func_key_type.get(context.call_function_name_qual)
    if key_type in ['DSA', 'RSA']:
        key_size = (context.get_call_arg_value('key_size') or
                    context.get_call_arg_at_position(arg_position[key_type]) or
                    2048)
        return _classify_key_size(key_type, key_size)
    elif key_type == 'EC':
        curve_key_sizes = {
            'SECP192R1': 192,
            'SECT163K1': 163,
            'SECT163R2': 163,
        }
        curve = context.call_args[arg_position[key_type]]
        key_size = curve_key_sizes[curve] if curve in curve_key_sizes else 224
        return _classify_key_size(key_type, key_size)


def _weak_crypto_key_size_pycrypto(context):
    func_key_type = {
        'Crypto.PublicKey.DSA.generate': 'DSA',
        'Crypto.PublicKey.RSA.generate': 'RSA',
    }
    key_type = func_key_type.get(context.call_function_name_qual)
    if key_type:
        key_size = (context.get_call_arg_value('bits') or
                    context.get_call_arg_at_position(0) or
                    2048)
        return _classify_key_size(key_type, key_size)


@checks('Call')
def weak_cryptographic_key(context):
    return (_weak_crypto_key_size_cryptography_io(context) or
            _weak_crypto_key_size_pycrypto(context))
