#
# Copyright 2016 Hewlett-Packard Enterprise
#
# SPDX-License-Identifier: Apache-2.0
import importlib
import logging
from unittest import mock

import testtools
import yaml

from bandit.cli import config_generator
from bandit.core import extension_loader
from bandit.core import test_properties as test


def gen_config(name):
    return {"test": "test data"}


@test.takes_config("test")
@test.checks("Str")
def _test_plugin(context, conf):
    pass


class BanditConfigGeneratorLoggerTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.logger = logging.getLogger(config_generator.__name__)
        self.original_logger_handlers = self.logger.handlers
        self.original_logger_level = self.logger.level
        self.logger.handlers = []

    def tearDown(self):
        super().tearDown()
        self.logger.handlers = self.original_logger_handlers
        self.logger.level = self.original_logger_level

    def test_init_logger(self):
        # Test that a logger was properly initialized
        config_generator.init_logger()
        self.assertIsNotNone(self.logger)
        self.assertNotEqual([], self.logger.handlers)
        self.assertEqual(logging.INFO, self.logger.level)


class BanditConfigGeneratorTests(testtools.TestCase):
    @mock.patch("sys.argv", ["bandit-config-generator"])
    def test_parse_args_no_defaults(self):
        # Without arguments, the generator should just show help and exit
        self.assertRaises(SystemExit, config_generator.parse_args)

    @mock.patch("sys.argv", ["bandit-config-generator", "--show-defaults"])
    def test_parse_args_show_defaults(self):
        # Test that the config generator does show default plugin settings
        return_value = config_generator.parse_args()
        self.assertTrue(return_value.show_defaults)

    @mock.patch("sys.argv", ["bandit-config-generator", "--out", "dummyfile"])
    def test_parse_args_out_file(self):
        # Test config generator get proper output file when specified
        return_value = config_generator.parse_args()
        self.assertEqual("dummyfile", return_value.output_file)

    def test_get_config_settings(self):
        config = {}
        for plugin in extension_loader.MANAGER.plugins:
            function = plugin.plugin
            if hasattr(plugin.plugin, "_takes_config"):
                module = importlib.import_module(function.__module__)
                config[plugin.name] = module.gen_config(function._takes_config)
        settings = config_generator.get_config_settings()
        self.assertEqual(
            yaml.safe_dump(config, default_flow_style=False), settings
        )

    @mock.patch("sys.argv", ["bandit-config-generator", "--show-defaults"])
    def test_main_show_defaults(self):
        # Test that the config generator does show defaults and returns 0
        with mock.patch(
            "bandit.cli.config_generator.get_config_settings"
        ) as mock_config_settings:
            return_value = config_generator.main()
            # The get_config_settings function should have been called
            self.assertTrue(mock_config_settings.called)
            self.assertEqual(0, return_value)
