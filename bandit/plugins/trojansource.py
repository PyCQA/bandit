# -*- coding:utf-8 -*-
#

r"""
=====================================================
B113: TrojanSource - Bidirectional control characters
=====================================================

This plugin checks for the presence of unicode bidirectional control characters
in Python source files. Those characters can be embedded in comments and strings
to reorder source code characters in a way that changes its logic.

:Example:

.. code-block:: none

    >> Issue: [B113:trojansource] A Python source file contains bidirectional control characters ('\u202e').
       Severity: High   Confidence: Medium
       Location: examples/trojansource.py:0:0

.. seealso::

 .. [1] https://trojansource.codes/
 .. [2] https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42574

.. versionadded:: 1.7.2

"""  # noqa: E501

from tokenize import detect_encoding

import bandit
from bandit.core import test_properties as test


BIDI_CHARACTERS = ('\u202A', '\u202B', '\u202C', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069')


@test.test_id('B113')
@test.checks('File')
def trojansource(context):
    with open(context.filename, 'rb') as src_file:
        encoding, _ = detect_encoding(src_file.readline)
    with open(context.filename, encoding=encoding) as src_file:
        for lineno, line in enumerate(src_file.readlines(), start=1):
            for char in BIDI_CHARACTERS:
                try:
                    col_offset = line.index(char) + 1
                except ValueError:
                    continue
                return bandit.Issue(
                    severity=bandit.HIGH,
                    confidence=bandit.MEDIUM,
                    text="A Python source file contains bidirectional control characters (%r)." % char,
                    lineno=lineno,
                    col_offset=col_offset,
                )
