#
# SPDX-License-Identifier: Apache-2.0
r"""
============================================================================
B324: Test use of insecure md4, md5, or sha1 hash functions in hashlib.new()
============================================================================

This plugin checks for the usage of the insecure MD4, MD5, or SHA1 hash
functions in ``hashlib.new`` function. The ``hashlib.new`` function provides
the ability to construct a new hashing object using the named algorithm. This
can be used to create insecure hash functions like MD4 and MD5 if they are
passed as algorithm names to this function.

This is similar to B303 blacklist check, except that this checks for insecure
hash functions created using ``hashlib.new`` function.

:Example:

    >> Issue: [B324:hashlib_new] Use of insecure MD4 or MD5 hash function.
       Severity: Medium   Confidence: High
       CWE: CWE-327 (https://cwe.mitre.org/data/definitions/327.html)
       Location: examples/hashlib_new_insecure_funcs.py:3
    2
    3  md5_hash = hashlib.new('md5', string='test')
    4  print(md5_hash)

.. seealso::

 - https://cwe.mitre.org/data/definitions/327.html

.. versionadded:: 1.5.0

.. versionchanged:: 1.7.3
    CWE information added

"""
import sys

import bandit
from bandit.core import issue
from bandit.core import test_properties as test


@test.test_id("B324")
@test.checks("Call")
def hashlib_new(context):
    if isinstance(context.call_function_name_qual, str):
        qualname_list = context.call_function_name_qual.split(".")
        func = qualname_list[-1]
        if "hashlib" in qualname_list and func == "new":
            args = context.call_args
            keywords = context.call_keywords
            name = args[0] if args else keywords["name"]
            if isinstance(name, str) and name.lower() in (
                "md4",
                "md5",
                "sha",
                "sha1",
            ):
                if sys.version_info >= (3, 9):
                    # Python 3.9 includes a usedforsecurity argument
                    usedforsecurity = (
                        args[2]
                        if len(args) > 2
                        else keywords.get("usedforsecurity", "True")
                    )

                    if usedforsecurity == "True":
                        return bandit.Issue(
                            severity=bandit.HIGH,
                            confidence=bandit.HIGH,
                            cwe=issue.Cwe.BROKEN_CRYPTO,
                            text="Use of insecure MD2, MD4, MD5, or SHA1 hash "
                            "function.",
                            lineno=context.node.lineno,
                        )
                else:
                    return bandit.Issue(
                        severity=bandit.MEDIUM,
                        confidence=bandit.HIGH,
                        cwe=issue.Cwe.BROKEN_CRYPTO,
                        text="Use of insecure MD2, MD4, MD5, or SHA1 hash "
                        "function.",
                        lineno=context.node.lineno,
                    )
