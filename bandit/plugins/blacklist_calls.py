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
A number of Python methods and functions are known to have potential security
implications. The blacklist calls plugin test is designed to detect the use of
these methods by scanning code for method calls and checking for their presence
in a configurable blacklist. The scanned calls are fully qualified and
de-aliased prior to checking. To illustrate this, imagine a check for
"evil.thing()" running on the following example code:

.. code-block:: python

    import evil as good

    good.thing()
    thing()

This would generate a warning about calling `evil.thing()` despite the module
being aliased as `good`. It would also not generate a warning on the call to
`thing()` in the local module, as it's fully qualified name will not match.

Each of the provided blacklisted calls can be grouped such that they generate
appropriate warnings (message, severity) and a token `{func}` may be used
in the provided output message, to be replaced with the actual method name.

Due to the nature of the test, confidence is always reported as HIGH

Config Options
--------------
.. code-block:: yaml

    blacklist_calls:
        bad_name_sets:
            - pickle:
                qualnames:
                    - pickle.loads
                    - pickle.load
                    - pickle.Unpickler
                    - cPickle.loads
                    - cPickle.load
                    - cPickle.Unpickler
                message: >
                    Pickle library appears to be in use, possible security
                    issue.
            - marshal:
                qualnames: [marshal.load, marshal.loads]
                message: >
                    Deserialization with the {func} is possibly dangerous.
                level: LOW

Sample Output
-------------
.. code-block:: none

      >> Issue: Pickle library appears to be in use, possible security issue.

        Severity: Medium   Confidence: High
        Location: ./examples/pickle_deserialize.py:20
      19  serialized = cPickle.dumps({(): []})
      20  print(cPickle.loads(serialized))
      21

References
----------
- https://security.openstack.org

.. versionadded:: 0.9.0

"""

import fnmatch

import bandit
from bandit.core import test_properties as test


_cached_blacklist_checks = []
_cached_blacklist_config = None


@test.takes_config
@test.checks('Call')
@test.test_id('B301')
def blacklist_calls(context, config):
    _ensure_cache(config)
    checks = _cached_blacklist_checks

    # for each check, go through and see if it matches all qualifications
    for qualnames, names, message_tpl, level, params in checks:
        confidence = 'HIGH'
        does_match = True
        # item 0=qualnames, 1=names, 2=message, 3=level, 4=params
        if does_match and qualnames:
            # match the qualname - respect wildcards if present
            does_match = any(
                fnmatch.fnmatch(context.call_function_name_qual, qn)
                for qn in qualnames)

        if does_match and names:
            does_match = any(context.call_function_name == n for n in names)

        if does_match and params:
            matched_p = False
            for p in params:
                for arg_num in range(0, context.call_args_count - 1):
                    if p == context.get_call_arg_at_position(arg_num):
                        matched_p = True
            if not matched_p:
                does_match = False

        if does_match:
            message = message_tpl.replace("{func}",
                                          context.call_function_name_qual)

            return bandit.Issue(
                severity=level, confidence=confidence,
                text=message,
                ident=context.call_function_name_qual
            )


def _ensure_cache(config):
    global _cached_blacklist_config
    if _cached_blacklist_checks and config is _cached_blacklist_config:
        return

    _cached_blacklist_config = config
    if config is not None and 'bad_name_sets' in config:
        sets = config['bad_name_sets']
    else:
        sets = []

    # load all the checks from the config file
    for cur_item in sets:
        for blacklist_item in cur_item:
            blacklist_object = cur_item[blacklist_item]
            cur_check = _get_tuple_for_item(blacklist_object)
            # skip bogus checks
            if cur_check:
                _cached_blacklist_checks.append(cur_check)


def _get_tuple_for_item(blacklist_object):
    level_map = {'LOW': bandit.LOW, 'MEDIUM': bandit.MEDIUM,
                 'HIGH': bandit.HIGH}

    # if the item we got passed isn't a dictionary, do nothing with this object
    if not isinstance(blacklist_object, dict):
        return None

    # not all of the fields will be set, so all have default fallbacks
    qualnames = blacklist_object.get('qualnames')
    names = blacklist_object.get('names')
    message = blacklist_object.get('message', '')
    params = blacklist_object.get('params')

    level_name = blacklist_object.get('level', 'MEDIUM').upper()
    level = level_map.get(level_name, 'MEDIUM')

    return (qualnames, names, message, level, params)
