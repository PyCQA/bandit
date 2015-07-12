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

import os.path
import warnings

from appdirs import site_data_dir

import bandit
from bandit.core.test_properties import *


def find_word_list(cfg_word_list_f):
    if not isinstance(cfg_word_list_f, str):
        return None
    try:
        cfg_word_list_f % {'site_data_dir': ''}
    except TypeError:
        return cfg_word_list_f

    site_data_dirs = ['.'] + site_data_dir("bandit", "",
                                           multipath=True).split(':')
    for dir in site_data_dirs:
        word_list_path = cfg_word_list_f % {'site_data_dir': dir}
        if os.path.isfile(word_list_path):
            if dir == ".":
                warnings.warn("Using relative path for word_list: %s"
                              % word_list_path)
            return word_list_path

    raise RuntimeError("Could not substitute '%(site_data_dir)s' "
                       "to a path with a valid word_list file")


@takes_config
@checks('Str')
def hardcoded_password(context, config):
    word_list_file = None
    word_list = []
    # try to read the word list file from config
    if (config is not None and 'word_list' in config):
        try:
            word_list_file = find_word_list(config['word_list'])
        except RuntimeError as e:
            warnings.warn(e.message)
            return

    # try to open the word list file and read passwords from it
    try:
        f = open(word_list_file, 'r')
    except (OSError, IOError):
        raise RuntimeError("Could not open word_list (from config"
                           " file): %s" % word_list_file)
    else:
        for word in f:
            word_list.append(word.strip())
        f.close()

    # for every password in the list, check against the current string
    for word in word_list:
        if context.string_val and context.string_val == word:
            return bandit.Issue(
                severity=bandit.LOW,
                confidence=bandit.LOW,
                text="Possible hardcoded password '(%s)'" % word
            )
