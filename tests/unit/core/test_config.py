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
import textwrap
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
        sample_yaml = textwrap.dedent("""
            %s:
                %s: %s
            """ % (self.example_key, self.example_subkey,
                   self.example_subvalue))

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
        test_yaml = 'key: value'
        f = self.useFixture(TempFile(test_yaml))
        self.b_config = config.BanditConfig(f.name)

    def test_not_exist(self):
        # get_setting() when the name doesn't exist returns None

        sample_setting_name = uuid.uuid4().hex
        self.assertIsNone(self.b_config.get_setting(sample_setting_name))


class TestConfigCompat(testtools.TestCase):
    sample_yaml = textwrap.dedent("""
        profiles:
            test_1:
                include:
                    - any_other_function_with_shell_equals_true
                    - assert_used
                exclude:

            test_2:
                include:
                    - blacklist_calls

            test_3:
                include:
                    - blacklist_imports

            test_4:
                exclude:
                    - assert_used

            test_5:
                exclude:
                    - blacklist_calls
                    - blacklist_imports

        blacklist_calls:
            bad_name_sets:
                - pickle:
                    qualnames: [pickle.loads]
                    message: "{func} library appears to be in use."

        blacklist_imports:
            bad_import_sets:
                - telnet:
                    imports: [telnetlib]
                    level: HIGH
                    message: "{module} is considered insecure."
        """)

    def setUp(self):
        super(TestConfigCompat, self).setUp()
        f = self.useFixture(TempFile(self.sample_yaml))
        self.config = config.BanditConfig(f.name)

    def test_converted_include(self):
        profiles = self.config.get_option('profiles')
        test = profiles['test_1']
        data = {'blacklist': {},
                'exclude': set(),
                'include': set(['B101', 'B604'])}

        self.assertEqual(data, test)

    def test_converted_exclude(self):
        profiles = self.config.get_option('profiles')
        test = profiles['test_4']

        self.assertEqual(set(['B101']), test['exclude'])

    def test_converted_blacklist_call_data(self):
        profiles = self.config.get_option('profiles')
        test = profiles['test_2']
        data = {'Call': [{'qualnames': ['telnetlib'],
                          'level': 'HIGH',
                          'message': '{name} is considered insecure.',
                          'name': 'telnet'}]}

        self.assertEqual(data, test['blacklist'])

    def test_converted_blacklist_import_data(self):
        profiles = self.config.get_option('profiles')
        test = profiles['test_3']
        data = [{'message': '{name} library appears to be in use.',
                 'name': 'pickle',
                 'qualnames': ['pickle.loads']}]

        self.assertEqual(data, test['blacklist']['Call'])
        self.assertEqual(data, test['blacklist']['Import'])
        self.assertEqual(data, test['blacklist']['ImportFrom'])

    def test_converted_blacklist_call_test(self):
        profiles = self.config.get_option('profiles')
        test = profiles['test_2']

        self.assertEqual(set(['B001']), test['include'])

    def test_converted_blacklist_import_test(self):
        profiles = self.config.get_option('profiles')
        test = profiles['test_3']

        self.assertEqual(set(['B001']), test['include'])

    def test_converted_exclude_blacklist(self):
        profiles = self.config.get_option('profiles')
        test = profiles['test_5']

        self.assertEqual(set(['B001']), test['exclude'])
