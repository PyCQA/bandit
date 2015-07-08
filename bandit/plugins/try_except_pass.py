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

import ast

import bandit
from bandit.core import test_properties


@test_properties.takes_config
@test_properties.checks('ExceptHandler')
def try_except_pass(context, config):
    node = context.node
    if len(node.body) == 1:
        if (not config['check_typed_exception'] and
           node.type is not None and
           node.type.id != 'Exception'):
                return

        if isinstance(node.body[0], ast.Pass):
            return bandit.Issue(
                severity=bandit.LOW,
                confidence=bandit.HIGH,
                text=("Try, Except, Pass detected.")
            )
