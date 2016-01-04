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

r"""
Description
-----------
Running Flask applications in debug mode results in the Werkzeug debugger
being enabled. This includes a feature that allows arbitrary code execution.
Documentation for both Flask [1]_ and Werkzeug [2]_ strongly suggests that
debug mode should never be enabled on production systems.

Operating a production server with debug mode enabled was the probable cause
of the Patreon breach in 2015 [3]_.

Config Options
--------------
None

Sample Output
-------------
.. code-block:: none

    >> Issue: A Flask app appears to be run with debug=True, which exposes
    the Werkzeug debugger and allows the execution of arbitrary code.
       Severity: High   Confidence: High
          Location: examples/flask_debug.py:10
          9 #bad
          10    app.run(debug=True)
          11

References
----------
.. [1] http://flask.pocoo.org/docs/0.10/quickstart/#debug-mode
.. [2] http://werkzeug.pocoo.org/docs/0.10/debug/
.. [3] http://labs.detectify.com/post/130332638391/how-patreon-got-hacked-publicly-exposed-werkzeug  # noqa

.. versionadded:: 0.15.0

"""

import bandit
from bandit.core import test_properties as test


@test.test_id('B201')
@test.checks('Call')
def flask_debug_true(context):
    if context.is_module_imported_like('flask'):
        if context.call_function_name_qual.endswith('.run'):
            if context.check_call_arg_value('debug', 'True'):
                return bandit.Issue(
                    severity=bandit.HIGH,
                    confidence=bandit.MEDIUM,
                    text="A Flask app appears to be run with debug=True, "
                         "which exposes the Werkzeug debugger and allows "
                         "the execution of arbitrary code.",
                    lineno=context.get_lineno_for_call_arg('debug'),
                )
