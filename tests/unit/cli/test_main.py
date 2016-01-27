#    Copyright 2016 IBM Corp.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging
import os

import fixtures
import testtools

from bandit.cli import main as bandit


class BanditCLIMainLoggerTests(testtools.TestCase):

    def setUp(self):
        super(BanditCLIMainLoggerTests, self).setUp()
        self.logger = logging.getLogger()
        self.original_logger_handlers = self.logger.handlers
        self.original_logger_level = self.logger.level
        self.logger.handlers = []

    def tearDown(self):
        super(BanditCLIMainLoggerTests, self).tearDown()
        self.logger.handlers = self.original_logger_handlers
        self.logger.level = self.original_logger_level

    def test_init_logger(self):
        # Test that a logger was properly initialized
        bandit._init_logger(False)

        self.assertIsNotNone(self.logger)
        self.assertNotEqual(self.logger.handlers, [])
        self.assertEqual(self.logger.level, logging.INFO)

    def test_init_logger_debug_mode(self):
        # Test that the logger's level was set at 'DEBUG'
        bandit._init_logger(True)
        self.assertEqual(self.logger.level, logging.DEBUG)


class BanditCLIMainTests(testtools.TestCase):

    def test_get_options_from_ini_no_ini_path_no_target(self):
        # Test that no config options are loaded when no ini path or target
        # directory are provided
        self.assertIsNone(bandit._get_options_from_ini(None, []))

    def test_get_options_from_ini_empty_directory_no_target(self):
        # Test that no config options are loaded when an empty directory is
        # provided as the ini path and no target directory is provided
        ini_directory = self.useFixture(fixtures.TempDir()).path
        self.assertIsNone(bandit._get_options_from_ini(ini_directory, []))

    def test_get_options_from_ini_no_ini_path_no_bandit_files(self):
        # Test that no config options are loaded when no ini path is provided
        # and the target directory contains no bandit config files (.bandit)
        target_directory = self.useFixture(fixtures.TempDir()).path
        self.assertIsNone(bandit._get_options_from_ini(None,
                          [target_directory]))

    def test_get_options_from_ini_no_ini_path_multi_bandit_files(self):
        # Test that bandit exits when no ini path is provided and the target
        # directory(s) contain multiple bandit config files (.bandit)
        target_directory = self.useFixture(fixtures.TempDir()).path
        second_config = 'second_config_directory'
        os.mkdir(os.path.join(target_directory, second_config))
        bandit_config_one = os.path.join(target_directory, '.bandit')
        bandit_config_two = os.path.join(target_directory, second_config,
                                         '.bandit')
        bandit_files = [bandit_config_one, bandit_config_two]
        with open('examples/nonsense.py') as fd:
            nonsense_file_contents = fd.read()
        for bandit_file in bandit_files:
            with open(bandit_file, 'wt') as fd:
                fd.write(nonsense_file_contents)
        self.assertRaisesRegex(SystemExit, '2', bandit._get_options_from_ini,
                               None, [target_directory])
