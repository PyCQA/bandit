# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
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
Description
-----------
The use of hard-coded passwords increases the possibility of password guessing
tremendously. This plugin test looks for all string literals and checks to see
if they exist in a list of likely default passwords. If they are found in the
list, a LOW severity issue is reported.

Note: this test is very noisy and likely to result in many false positives.

Config Options
--------------
This plugin test takes a similarly named config block, `hardcoded_password`.
Here a path, `word_list`, can be given to indicate where the default password
word list file may be found.

.. code-block:: yaml

    hardcoded_password:
        # Support for full path, relative path and special "%(site_data_dir)s"
        # substitution (/usr/{local}/share)
        word_list: "%(site_data_dir)s/wordlist/default-passwords"


Sample Output
-------------
.. code-block:: none

    >> Issue: Possible hardcoded password '(root)'
       Severity: Low   Confidence: Low
       Location: ./examples/hardcoded-passwords.py:5
    4 def someFunction2(password):
    5     if password == "root":
    6         print("OK, logged in")

References
----------
- https://www.owasp.org/index.php/Use_of_hard-coded_password

.. versionadded:: 0.9.0

"""

import sys

import bandit
from bandit.core.test_properties import *


candidates = set(["password", "pass", "passwd", "pwd", "secret", "token",
                  "secrete"])


def _report(value):
    return bandit.Issue(
        severity=bandit.LOW,
        confidence=bandit.MEDIUM,
        text=("Possible hardcoded password: '%s'" % value))


@checks('Str')
def hardcoded_password_string(context):
    node = context.node
    if isinstance(node.parent, ast.Assign):
        # looks for "candidate='some_string'"
        for targ in node.parent.targets:
            if isinstance(targ, ast.Name) and targ.id in candidates:
                return _report(node.s)

    elif isinstance(node.parent, ast.Index) and node.s in candidates:
        # looks for "dict[candidate]='some_string'"
        # assign -> subscript -> index -> string
        assign = node.parent.parent.parent
        if isinstance(assign, ast.Assign) and isinstance(assign.value,
                                                         ast.Str):
            return _report(assign.value.s)

    elif isinstance(node.parent, ast.Compare):
        # looks for "candidate == 'some_string'"
        comp = node.parent
        if isinstance(comp.left, ast.Name) and comp.left.id in candidates:
            if isinstance(comp.comparators[0], ast.Str):
                return _report(comp.comparators[0].s)


@checks('Call')
def hardcoded_password_funcarg(context):
    # looks for "function(candidate='some_string')"
    for kw in context.node.keywords:
        if isinstance(kw.value, ast.Str) and kw.arg in candidates:
            return _report(kw.value.s)


@checks('FunctionDef')
def hardcoded_password_default(context):
    # looks for "def function(candidate='some_string')"

    # this pads the list of default values with "None" if nothing is given
    defs = [None] * (len(context.node.args.args) -
                     len(context.node.args.defaults))
    defs.extend(context.node.args.defaults)

    # go through all (param, value)s and look for candidates
    for key, val in zip(context.node.args.args, defs):
        if isinstance(key, ast.Name):
            check = key.arg if sys.version_info.major > 2 else key.id  # Py3
            if isinstance(val, ast.Str) and check in candidates:
                return _report(val.s)
