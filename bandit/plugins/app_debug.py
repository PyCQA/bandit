# -*- coding:utf-8 -*-
#
# Copyright 2015 Hewlett-Packard Development Company, L.P.
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

import bandit
from bandit.core.test_properties import checks


@checks('Call')
def flask_debug_true(context):
    if context.is_module_imported_like('flask'):
        if context.call_function_name_qual.endswith('.run'):
            if context.check_call_arg_value('debug', 'True'):
                return bandit.Issue(
                    severity=bandit.HIGH,
                    confidence=bandit.MEDIUM,
                    text="A Flask app appears to be run with debug=True, "
                         "which exposes the Werkzeug debugger and allows "
                         "the execution of arbitrary code."
                )
