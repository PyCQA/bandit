# -*- coding:utf-8 -*-
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

r"""
==========================================================================
B324: Test for use of insecure md4 and md5 hash functions in hashlib.new()
==========================================================================

This plugin checks for the usage of the insecure MD4 and MD5 hash functions
in ``hashlib.new`` function. The ``hashlib.new`` function provides the ability
to construct a new hashing object using the named algorithm. This can be used
to create insecure hash functions like MD4 and MD5 if they are passed as
algorithm names to this function.

This is similar to B303 blacklist check, except that this checks for insecure
hash functions created using ``hashlib.new`` function.

:Example:

    >> Issue: [B324:hashlib_new] Use of insecure MD4 or MD5 hash function.
       Severity: Medium   Confidence: High
       Location: examples/hashlib_new_insecure_funcs.py:3
    2
    3  md5_hash = hashlib.new('md5', string='test')
    4  print(md5_hash)


.. versionadded:: 1.5.0

"""

import bandit
from bandit.core import test_properties as test


@test.test_id('B324')
@test.checks('Call')
def hashlib_new(context):
    if isinstance(context.call_function_name_qual, str):
        qualname_list = context.call_function_name_qual.split('.')
        func = qualname_list[-1]
        if 'hashlib' in qualname_list and func == 'new':
            args = context.call_args
            keywords = context.call_keywords
            name = args[0] if args else keywords['name']
            if name.lower() in ('md4', 'md5'):
                return bandit.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.HIGH,
                    text="Use of insecure MD4 or MD5 hash function.",
                    lineno=context.node.lineno,
                )
