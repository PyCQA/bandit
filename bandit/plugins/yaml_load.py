# -*- coding:utf-8 -*-
#
# Copyright (c) 2016 Rackspace, Inc.
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
===============================
B506: Test for use of yaml load
===============================

This plugin test checks for the unsafe usage of the ``yaml.load`` function from
the PyYAML package. The yaml.load function provides the ability to construct
an arbitrary Python object, which may be dangerous if you receive a YAML
document from an untrusted source. The function yaml.safe_load limits this
ability to simple Python objects like integers or lists.

Please see
http://pyyaml.org/wiki/PyYAMLDocumentation#LoadingYAML for more information
on ``yaml.load`` and yaml.safe_load

:Example:

    >> Issue: [yaml_load] Use of unsafe yaml load. Allows instantiation of
       arbitrary objects. Consider yaml.safe_load().
       Severity: Medium   Confidence: High
       Location: examples/yaml_load.py:5
    4 ystr = yaml.dump({'a' : 1, 'b' : 2, 'c' : 3})
    5 y = yaml.load(ystr)
    6 yaml.dump(y)


.. seealso::

 - http://pyyaml.org/wiki/PyYAMLDocumentation#LoadingYAML

.. versionadded:: 1.0.0

"""

import bandit
from bandit.core import test_properties as test


@test.test_id('B506')
@test.checks('Call')
def yaml_load(context):
    if type(context.call_function_name_qual) == str:
        qualname_list = context.call_function_name_qual.split('.')
        func = qualname_list[-1]
        if 'yaml' in qualname_list and func == 'load':
            if not context.check_call_arg_value('Loader', 'SafeLoader'):
                return bandit.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.HIGH,
                    text="Use of unsafe yaml load. Allows instantiation of"
                         " arbitrary objects. Consider yaml.safe_load().",
                    lineno=context.node.lineno,
                )
