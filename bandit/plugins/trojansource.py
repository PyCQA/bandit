#
# SPDX-License-Identifier: Apache-2.0
r"""
=====================================================
B613: TrojanSource - Bidirectional control characters
=====================================================

This plugin checks for the presence of unicode bidirectional control characters
in Python source files. Those characters can be embedded in comments and strings
to reorder source code characters in a way that changes its logic.

:Example:

.. code-block:: none

    >> Issue: [B613:trojansource] A Python source file contains bidirectional control characters ('\u202e').
       Severity: High   Confidence: Medium
       CWE: CWE-838 (https://cwe.mitre.org/data/definitions/838.html)
       More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b113_trojansource.html
       Location: examples/trojansource.py:4:25
     3  	access_level = "user"
     4	    if access_level != 'none‮⁦': # Check if admin ⁩⁦' and access_level != 'user
     5	        print("You are an admin.\n")

.. seealso::

 .. [1] https://trojansource.codes/
 .. [2] https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42574

.. versionadded:: 1.7.10

"""  # noqa: E501
from tokenize import detect_encoding

import bandit
from bandit.core import issue
from bandit.core import test_properties as test


BIDI_CHARACTERS = (
    "\u202A",
    "\u202B",
    "\u202C",
    "\u202D",
    "\u202E",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
    "\u200F",
)


@test.test_id("B613")
@test.checks("File")
def trojansource(context):
    with open(context.filename, "rb") as src_file:
        encoding, _ = detect_encoding(src_file.readline)
    with open(context.filename, encoding=encoding) as src_file:
        for lineno, line in enumerate(src_file.readlines(), start=1):
            for char in BIDI_CHARACTERS:
                try:
                    col_offset = line.index(char) + 1
                except ValueError:
                    continue
                text = (
                    "A Python source file contains bidirectional"
                    " control characters (%r)." % char
                )
                return bandit.Issue(
                    severity=bandit.HIGH,
                    confidence=bandit.MEDIUM,
                    cwe=issue.Cwe.INAPPROPRIATE_ENCODING_FOR_OUTPUT_CONTEXT,
                    text=text,
                    lineno=lineno,
                    col_offset=col_offset,
                )
