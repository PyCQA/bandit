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

import bandit
from bandit.core.test_properties import *


@takes_config
@checks('Call')
def blacklist_calls(context, config):
    if config is not None and 'bad_name_sets' in config:
        sets = config['bad_name_sets']
    else:
        sets = []

    checks = []

    # load all the checks from the config file
    for cur_item in sets:
        for blacklist_item in cur_item:
            blacklist_object = cur_item[blacklist_item]
            cur_check = _get_tuple_for_item(blacklist_object)
            # skip bogus checks
            if cur_check:
                checks.append(cur_check)

    # for each check, go through and see if it matches all qualifications
    for check in checks:
        confidence = 'HIGH'
        does_match = True
        # item 0=qualnames, 1=names, 2=message, 3=level, 4=params
        if does_match and check[0]:
            matched_qn = False
            for qn in check[0]:
                if context.call_function_name_qual == qn:
                    matched_qn = True
            if not matched_qn:
                does_match = False

        if does_match and check[1]:
            matched_n = False
            for n in check[1]:
                if context.call_function_name == n:
                    matched_n = True
            if not matched_n:
                does_match = False

        if does_match and check[4]:
            matched_p = False
            for p in check[4]:
                for arg_num in range(0, context.call_args_count - 1):
                    if p == context.get_call_arg_at_position(arg_num):
                        matched_p = True
            if not matched_p:
                does_match = False

        if does_match:
            level = None
            if check[3] == 'HIGH':
                level = bandit.HIGH
            elif check[3] == 'MEDIUM':
                level = bandit.MEDIUM
            elif check[3] == 'LOW':
                level = bandit.LOW

            message = check[2].replace("{func}",
                                       context.call_function_name_qual)

            return bandit.Issue(
                severity=level, confidence=confidence,
                text="%s  %s" % (message, context.call_args_string)
            )


def _get_tuple_for_item(blacklist_object):
    # defaults, one or more of these are likely to not be set, so they won't be
    # checked
    qualnames = None
    names = None
    message = ""
    level = 'MEDIUM'
    params = None

    # if the item we got passed isn't a dictionary, do nothing with this object
    if not isinstance(blacklist_object, dict):
        return None

    if 'qualnames' in blacklist_object:
        qualnames = blacklist_object['qualnames']
    if 'names' in blacklist_object:
        names = blacklist_object['names']
    if 'message' in blacklist_object:
        message = blacklist_object['message']

    if 'level' in blacklist_object:
        _level = blacklist_object['level'].upper()
        if _level in {'HIGH', 'MEDIUM', 'LOW'}:
            level = _level

    if 'params' in blacklist_object:
        params = blacklist_object['params']

    return_tuple = (qualnames, names, message, level, params)
    return return_tuple
