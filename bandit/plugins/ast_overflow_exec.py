# -*- coding:utf-8 -*-
#
# Copyright 2018 Hewlett-Packard Development Company, L.P.
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

import six

import bandit
from bandit.core import test_properties as test


def ast_overflow_exec_issue():
    return bandit.Issue(
        severity=bandit.LOW,
        confidence=bandit.HIGH,
        text=('It is possible to crash the Python interpreter by passing '
              'sufficiently large/complex strings to ast.literal_eval(), '
              'ast.parse(), compile(), dbm.dumb.open(), eval() or exec() due '
              'to stack depth limitations in Python’s AST compiler. Ensure '
              'these functions are not used on untrusted data.')
    )


if six.PY2:
    @test.checks('Exec')
    @test.test_id('B326')
    def ast_overflow(context):
        return ast_overflow_exec_issue()
else:
    @test.checks('Call')
    @test.test_id('B326')
    def ast_overflow(context):
        if context.call_function_name_qual == 'exec':
            return ast_overflow_exec_issue()
