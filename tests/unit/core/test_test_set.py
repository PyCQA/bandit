# -*- coding:utf-8 -*-
#
# Copyright (c) 2016 Hewlett-Packard Development Company, L.P.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import mock
from stevedore import extension
import testtools

from bandit.core import extension_loader
from bandit.core import test_properties as test
from bandit.core import test_set


@test.checks('Str')
@test.test_id('B000')
def test_plugin():
    return {'Import': {}, 'ImportFrom': {}, 'Calls': {}}


class BanditTesSetTests(testtools.TestCase):
    def _make_test_manager(self, plugin):
        return extension.ExtensionManager.make_test_instance(
            [extension.Extension('test_plugin', None, test_plugin, None)])

    def setUp(self):
        super(BanditTesSetTests, self).setUp()
        mngr = self._make_test_manager(mock.MagicMock)
        self.patchExtMan = mock.patch('stevedore.extension.ExtensionManager')
        self.mockExtMan = self.patchExtMan.start()
        self.mockExtMan.return_value = mngr
        self.old_ext_man = extension_loader.MANAGER
        extension_loader.MANAGER = extension_loader.Manager()

    def tearDown(self):
        self.patchExtMan.stop()
        super(BanditTesSetTests, self).tearDown()
        extension_loader.MANAGER = self.old_ext_man

    def test_has_defaults(self):
        ts = test_set.BanditTestSet(mock.MagicMock())
        self.assertEqual(len(ts.get_tests('Str')), 1)

    def test_profile_include(self):
        profile = {'include': ['test_plugin']}
        ts = test_set.BanditTestSet(mock.MagicMock(), profile)
        self.assertEqual(len(ts.get_tests('Str')), 1)

    def test_profile_exclude(self):
        profile = {'exclude': ['test_plugin']}
        ts = test_set.BanditTestSet(mock.MagicMock(), profile)
        self.assertEqual(len(ts.get_tests('Str')), 0)

    def test_profile_include_none(self):
        profile = {'include': []}  # same as no include
        ts = test_set.BanditTestSet(mock.MagicMock(), profile)
        self.assertEqual(len(ts.get_tests('Str')), 1)

    def test_profile_exclude_none(self):
        profile = {'exclude': []}  # same as no exclude
        ts = test_set.BanditTestSet(mock.MagicMock(), profile)
        self.assertEqual(len(ts.get_tests('Str')), 1)

    def test_profile_has_builtin_blacklist(self):
        ts = test_set.BanditTestSet(mock.MagicMock())
        self.assertEqual(len(ts.get_tests('Import')), 1)
        self.assertEqual(len(ts.get_tests('ImportFrom')), 1)
        self.assertEqual(len(ts.get_tests('Calls')), 1)

    def test_profile_exclude_builtin_blacklist(self):
        profile = {'exclude': ['blacklist']}
        ts = test_set.BanditTestSet(mock.MagicMock(), profile)
        self.assertEqual(len(ts.get_tests('Import')), 0)
        self.assertEqual(len(ts.get_tests('ImportFrom')), 0)
        self.assertEqual(len(ts.get_tests('Calls')), 0)
