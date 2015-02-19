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
# tmcpeak - temporarily commenting this test out, it's broken
# @checks('Str')
def hardcoded_password(context, config):
    word_list_file = ""

    # try to read the word list file from config
    if(config is not None and 'word_list' in config and
            type(config['word_list']) == str):
        word_list_file = config['word_list']

    word_list = []

    # try to open the word list file and read passwords from it
    try:
        f = open(word_list_file, 'r')
    except (OSError, IOError):
        return
    else:
        for word in f:
            word_list.append(word.strip())
        f.close()

    # for every password in the list, check against the current string
    for word in word_list:
        if context.string_val and context.string_val == word:
            return bandit.WARN, "Possible hardcoded password '(%s)'" % word
