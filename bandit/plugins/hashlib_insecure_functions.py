#
# SPDX-License-Identifier: Apache-2.0
r"""
======================================================================
B324: Test use of insecure md4, md5, or sha1 hash functions in hashlib
======================================================================

This plugin checks for the usage of the insecure MD4, MD5, or SHA1 hash
functions in ``hashlib``. The ``hashlib.new`` function provides
the ability to construct a new hashing object using the named algorithm. This
can be used to create insecure hash functions like MD4 and MD5 if they are
passed as algorithm names to this function.

For Python versions prior to 3.9, this check is similar to B303 blacklist
except that this checks for insecure hash functions created using
``hashlib.new`` function. For Python version 3.9 and later, this check
does additional checking for usage of keyword usedforsecurity on all
function variations of hashlib.

:Example:

    >> Issue: [B324:hashlib] Use of weak MD4, MD5, or SHA1 hash for
       security. Consider usedforsecurity=False
       Severity: High   Confidence: High
       CWE: CWE-327 (https://cwe.mitre.org/data/definitions/327.html)
       Location: examples/hashlib_new_insecure_functions.py:3:0
       More Info: https://bandit.readthedocs.io/en/latest/plugins/b324_hashlib.html
    2
    3   hashlib.new('md5')
    4

.. seealso::

 - https://cwe.mitre.org/data/definitions/327.html

.. versionadded:: 1.5.0

.. versionchanged:: 1.7.3
    CWE information added

"""  # noqa: E501
import sys

import bandit
from bandit.core import issue
from bandit.core import test_properties as test


def _hashlib_func(context):
    if isinstance(context.call_function_name_qual, str):
        qualname_list = context.call_function_name_qual.split(".")

        if "hashlib" in qualname_list:
            func = qualname_list[-1]
            keywords = context.call_keywords

            if func in ("md4", "md5", "sha", "sha1"):
                if keywords.get("usedforsecurity", "True") == "True":
                    return bandit.Issue(
                        severity=bandit.HIGH,
                        confidence=bandit.HIGH,
                        cwe=issue.Cwe.BROKEN_CRYPTO,
                        text="Use of weak MD4, MD5, or SHA1 hash for "
                        "security. Consider usedforsecurity=False",
                        lineno=context.node.lineno,
                    )
            elif func == "new":
                args = context.call_args
                name = args[0] if args else keywords.get("name", None)
                if isinstance(name, str) and name.lower() in (
                    "md4",
                    "md5",
                    "sha",
                    "sha1",
                ):
                    if keywords.get("usedforsecurity", "True") == "True":
                        return bandit.Issue(
                            severity=bandit.HIGH,
                            confidence=bandit.HIGH,
                            cwe=issue.Cwe.BROKEN_CRYPTO,
                            text="Use of weak MD4, MD5, or SHA1 hash for "
                            "security. Consider usedforsecurity=False",
                            lineno=context.node.lineno,
                        )


def _hashlib_new(context):
    if isinstance(context.call_function_name_qual, str):
        qualname_list = context.call_function_name_qual.split(".")
        func = qualname_list[-1]

        if "hashlib" in qualname_list and func == "new":
            args = context.call_args
            keywords = context.call_keywords
            name = args[0] if args else keywords.get("name", None)
            if isinstance(name, str) and name.lower() in (
                "md4",
                "md5",
                "sha",
                "sha1",
            ):
                return bandit.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.HIGH,
                    cwe=issue.Cwe.BROKEN_CRYPTO,
                    text="Use of insecure MD4, MD5, or SHA1 hash function.",
                    lineno=context.node.lineno,
                )


@test.test_id("B324")
@test.checks("Call")
def hashlib(context):
    if sys.version_info >= (3, 9):
        return _hashlib_func(context)
    else:
        return _hashlib_new(context)
