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

import bandit
from bandit.core.test_properties import *


def _classify_key_size(key_type, key_size):
    key_sizes = {
        'DSA': [(1024, bandit.HIGH), (2048, bandit.MEDIUM)],
        'RSA': [(1024, bandit.HIGH), (2048, bandit.MEDIUM)],
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
    }
    arg_position = {
        'DSA': 0,
        'RSA': 1,
    }
    key_type = func_key_type.get(context.call_function_name_qual)
    if key_type:
        key_size = (context.get_call_arg_value('key_size') or
                    context.get_call_arg_at_position(arg_position[key_type]) or
                    2048)
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
