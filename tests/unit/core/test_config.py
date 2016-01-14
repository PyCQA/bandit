# Copyright 2015 IBM Corp.
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

import os
import tempfile
import uuid

import fixtures
import testtools

from bandit.core import config
from bandit.core import utils


class TempFile(fixtures.Fixture):
    def __init__(self, contents=None):
        super(TempFile, self).__init__()
        self.contents = contents

    def setUp(self):
        super(TempFile, self).setUp()

        with tempfile.NamedTemporaryFile(mode='wt', delete=False) as f:
            if self.contents:
                f.write(self.contents)

        self.addCleanup(os.unlink, f.name)

        self.name = f.name


class TestInit(testtools.TestCase):
    def test_settings(self):
        # Can initialize a BanditConfig.

        example_key = uuid.uuid4().hex
        example_value = self.getUniqueString()
        contents = '%s: %s' % (example_key, example_value)
        f = self.useFixture(TempFile(contents))
        b_config = config.BanditConfig(f.name)

        # After initialization, can get settings.
        self.assertEqual('*.py', b_config.get_setting('plugin_name_pattern'))

        self.assertEqual({example_key: example_value}, b_config.config)
        self.assertEqual(example_value, b_config.get_option(example_key))

    def test_file_does_not_exist(self):
        # When the config file doesn't exist, ConfigFileUnopenable is raised.

        cfg_file = os.path.join(os.getcwd(), 'notafile')
        self.assertRaisesRegex(utils.ConfigFileUnopenable, cfg_file,
                               config.BanditConfig, cfg_file)

    def test_yaml_invalid(self):
        # When the config yaml file isn't valid, sys.exit(2) is called.

        # The following is invalid because it starts a sequence and doesn't
        # end it.
        invalid_yaml = '- [ something'
        f = self.useFixture(TempFile(invalid_yaml))
        self.assertRaisesRegex(
            utils.ConfigFileInvalidYaml, f.name, config.BanditConfig, f.name)


class TestGetOption(testtools.TestCase):
    def setUp(self):
        super(TestGetOption, self).setUp()

        self.example_key = uuid.uuid4().hex
        self.example_subkey = uuid.uuid4().hex
        self.example_subvalue = uuid.uuid4().hex
        sample_yaml = """
%s:
    %s: %s
""" % (self.example_key, self.example_subkey, self.example_subvalue)
        f = self.useFixture(TempFile(sample_yaml))

        self.b_config = config.BanditConfig(f.name)

    def test_levels(self):
        # get_option with .-separated string.

        sample_option_name = '%s.%s' % (self.example_key, self.example_subkey)
        self.assertEqual(self.example_subvalue,
                         self.b_config.get_option(sample_option_name))

    def test_levels_not_exist(self):
        # get_option when option name doesn't exist returns None.

        sample_option_name = '%s.%s' % (uuid.uuid4().hex, uuid.uuid4().hex)
        self.assertIsNone(self.b_config.get_option(sample_option_name))


class TestGetSetting(testtools.TestCase):
    def setUp(self):
        super(TestGetSetting, self).setUp()
        f = self.useFixture(TempFile())
        self.b_config = config.BanditConfig(f.name)

    def test_not_exist(self):
        # get_setting() when the name doesn't exist returns None

        sample_setting_name = uuid.uuid4().hex
        self.assertIsNone(self.b_config.get_setting(sample_setting_name))
