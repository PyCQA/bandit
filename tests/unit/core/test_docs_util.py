# -*- coding:utf-8 -*-
#
# Copyright 2019 Victor Torre
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

import testtools

from bandit.core.docs_utils import BASE_URL, get_url


class UtilTests(testtools.TestCase):
    '''This set of tests exercises bandit.core.docs_util functions.'''

    def test_overwrite_bib_info(self):
        expected_url = BASE_URL + "blacklists/blacklist_call.html" \
                                  "#b304-b305-ciphers-and-modes"
        self.assertEqual(get_url('b304'), get_url('b305'))
        self.assertEqual(get_url('b304'), expected_url)

    def test_normal_call_bib(self):
        expected_url = BASE_URL + "blacklists/blacklist_call.html" \
                                  "#b401-import-telnetlib"
        self.assertEqual(get_url('b401'), expected_url)
