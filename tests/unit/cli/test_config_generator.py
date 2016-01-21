# -*- coding:utf-8 -*-
#
# Copyright 2016 Hewlett-Packard Enterprise
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

import mock
from stevedore import extension
import testtools

from bandit.cli import config_generator
from bandit.core import test_properties as test


def gen_config(name):
    return {"test": "test data"}


@test.takes_config('test')
@test.checks('Str')
def _test_plugin(context, conf):
    pass


class BanditConfigGeneratorTests(testtools.TestCase):
    def _make_test_manager(self, plugin):
        return extension.ExtensionManager.make_test_instance(
            [extension.Extension('test', None, _test_plugin, None)])

    def setUp(self):
        mngr = self._make_test_manager(mock.MagicMock)
        self.patchExtMan = mock.patch('stevedore.extension.ExtensionManager')
        self.mockExtMan = self.patchExtMan.start()
        self.mockExtMan.return_value = mngr
        super(BanditConfigGeneratorTests, self).setUp()

    def tearDown(self):
        super(BanditConfigGeneratorTests, self).tearDown()
        self.patchExtMan.stop()

    def test_get_config_settings(self):
        settings = config_generator.get_config_settings()
        self.assertEqual(settings, "test: {test: test data}\n")
