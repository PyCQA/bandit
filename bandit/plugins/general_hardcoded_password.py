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
        check = key.arg if sys.version_info.major > 2 else key.id  # Py3
        if isinstance(val, ast.Str) and check in candidates:
            return _report(val.s)
