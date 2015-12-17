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
Errors in Python code bases are typically communicated using ``Exceptions``.
An exception object is 'raised' in the event of an error and can be 'caught' at
a later point in the program, typically some error handling or logging action
will then be performed.

However, it is possible to catch an exception and silently ignore it. This is
illustrated with the following example

.. code-block:: python

    try:
      do_some_stuff()
    except Exception:
      pass

This pattern is considered bad practice in general, but also represents a
potential security issue. A larger than normal volume of errors from a service
can indicate an attempt is being made to disrupt or interfere with it. Thus
errors should, at the very least, be logged.

There are rare situations where it is desirable to suppress errors, but this is
typically done with specific exception types, rather than the base Exception
class (or no type). To accommodate this, the test may be configured to ignore
'try, except, pass' where the exception is typed. For example, the following
would not generate a warning if the configuration option
``checked_typed_exception`` is set to False:

.. code-block:: python

    try:
      do_some_stuff()
    except ZeroDivisionError:
      pass

Config Options
--------------
.. code-block:: yaml

    try_except_pass:
      check_typed_exception: True


Sample Output
-------------
.. code-block:: none

    >> Issue: Try, Except, Pass detected.
       Severity: Low   Confidence: High
       Location: ./examples/try_except_pass.py:4
    3        a = 1
    4    except:
    5        pass

References
----------
- https://security.openstack.org

.. versionadded:: 0.13.0

"""

import ast

import bandit
from bandit.core import test_properties as test


@test.takes_config
@test.checks('ExceptHandler')
@test.test_id('B110')
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
