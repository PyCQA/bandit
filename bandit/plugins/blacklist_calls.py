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

import fnmatch

import bandit
from bandit.core.test_properties import *


_cached_blacklist_checks = []
_cached_blacklist_config = None


@takes_config
@checks('Call')
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
