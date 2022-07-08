#    Copyright 2016 IBM Corp.
#
# SPDX-License-Identifier: Apache-2.0
import logging
import os
from unittest import mock

import fixtures
import testtools

from bandit.cli import main as bandit
from bandit.core import extension_loader as ext_loader
from bandit.core import utils

bandit_config_content = """
include:
    - '*.py'
    - '*.pyw'

profiles:
    test:
        include:
            - start_process_with_a_shell

shell_injection:
    subprocess:

    shell:
        - os.system
"""

bandit_baseline_content = """{
    "results": [
        {
            "code": "some test code",
            "filename": "test_example.py",
            "issue_severity": "low",
            "issue_confidence": "low",
            "issue_text": "test_issue",
            "test_name": "some_test",
            "test_id": "x",
            "line_number": "n",
            "line_range": "n-m"
        }
    ]
}
"""


class BanditCLIMainLoggerTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.logger = logging.getLogger()
        self.original_logger_handlers = self.logger.handlers
        self.original_logger_level = self.logger.level
        self.logger.handlers = []

    def tearDown(self):
        super().tearDown()
        self.logger.handlers = self.original_logger_handlers
        self.logger.level = self.original_logger_level

    def test_init_logger(self):
        # Test that a logger was properly initialized
        bandit._init_logger()

        self.assertIsNotNone(self.logger)
        self.assertNotEqual(self.logger.handlers, [])
        self.assertEqual(logging.INFO, self.logger.level)

    def test_init_logger_debug_mode(self):
        # Test that the logger's level was set at 'DEBUG'
        bandit._init_logger(logging.DEBUG)
        self.assertEqual(logging.DEBUG, self.logger.level)


class BanditCLIMainTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.current_directory = os.getcwd()

    def tearDown(self):
        super().tearDown()
        os.chdir(self.current_directory)

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
        self.assertIsNone(
            bandit._get_options_from_ini(None, [target_directory])
        )

    def test_get_options_from_ini_no_ini_path_multi_bandit_files(self):
        # Test that bandit exits when no ini path is provided and the target
        # directory(s) contain multiple bandit config files (.bandit)
        target_directory = self.useFixture(fixtures.TempDir()).path
        second_config = "second_config_directory"
        os.mkdir(os.path.join(target_directory, second_config))
        bandit_config_one = os.path.join(target_directory, ".bandit")
        bandit_config_two = os.path.join(
            target_directory, second_config, ".bandit"
        )
        bandit_files = [bandit_config_one, bandit_config_two]
        for bandit_file in bandit_files:
            with open(bandit_file, "wt") as fd:
                fd.write(bandit_config_content)
        self.assertRaisesRegex(
            SystemExit,
            "2",
            bandit._get_options_from_ini,
            None,
            [target_directory],
        )

    def test_init_extensions(self):
        # Test that an extension loader manager is returned
        self.assertEqual(ext_loader.MANAGER, bandit._init_extensions())

    def test_log_option_source_arg_val(self):
        # Test that the command argument value is returned when provided
        # with None or a string default value
        arg_val = "file"
        ini_val = "vuln"
        option_name = "aggregate"
        for default_val in (None, "default"):
            self.assertEqual(
                arg_val,
                bandit._log_option_source(
                    default_val, arg_val, ini_val, option_name
                ),
            )

    def test_log_option_source_ini_value(self):
        # Test that the ini value is returned when no command argument is
        # provided
        default_val = None
        ini_val = "vuln"
        option_name = "aggregate"
        self.assertEqual(
            ini_val,
            bandit._log_option_source(default_val, None, ini_val, option_name),
        )

    def test_log_option_source_ini_val_with_str_default_and_no_arg_val(self):
        # Test that the ini value is returned when no command argument is
        # provided
        default_val = "file"
        arg_val = "file"
        ini_val = "vuln"
        option_name = "aggregate"
        self.assertEqual(
            ini_val,
            bandit._log_option_source(
                default_val, arg_val, ini_val, option_name
            ),
        )

    def test_log_option_source_no_values(self):
        # Test that None is returned when no command argument or ini value are
        # provided
        option_name = "aggregate"
        self.assertIsNone(
            bandit._log_option_source(None, None, None, option_name)
        )

    @mock.patch("sys.argv", ["bandit", "-c", "bandit.yaml", "test"])
    def test_main_config_unopenable(self):
        # Test that bandit exits when a config file cannot be opened
        with mock.patch("bandit.core.config.__init__") as mock_bandit_config:
            mock_bandit_config.side_effect = utils.ConfigError("", "")
            # assert a SystemExit with code 2
            self.assertRaisesRegex(SystemExit, "2", bandit.main)

    @mock.patch("sys.argv", ["bandit", "-c", "bandit.yaml", "test"])
    def test_main_invalid_config(self):
        # Test that bandit exits when a config file contains invalid YAML
        # content
        with mock.patch(
            "bandit.core.config.BanditConfig.__init__"
        ) as mock_bandit_config:
            mock_bandit_config.side_effect = utils.ConfigError("", "")
            # assert a SystemExit with code 2
            self.assertRaisesRegex(SystemExit, "2", bandit.main)

    @mock.patch("sys.argv", ["bandit", "-c", "bandit.yaml", "test"])
    def test_main_handle_ini_options(self):
        # Test that bandit handles cmdline args from a bandit.yaml file
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "wt") as fd:
            fd.write(bandit_config_content)
        with mock.patch(
            "bandit.cli.main._get_options_from_ini"
        ) as mock_get_opts:
            mock_get_opts.return_value = {
                "exclude": "/tmp",
                "skips": "skip_test",
                "tests": "some_test",
            }

            with mock.patch("bandit.cli.main.LOG.error") as err_mock:
                # SystemExit with code 2 when test not found in profile
                self.assertRaisesRegex(SystemExit, "2", bandit.main)
                self.assertEqual(
                    str(err_mock.call_args[0][0]),
                    "Unknown test found in profile: some_test",
                )

    @mock.patch(
        "sys.argv", ["bandit", "-c", "bandit.yaml", "-t", "badID", "test"]
    )
    def test_main_unknown_tests(self):
        # Test that bandit exits when an invalid test ID is provided
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "wt") as fd:
            fd.write(bandit_config_content)
        # assert a SystemExit with code 2
        self.assertRaisesRegex(SystemExit, "2", bandit.main)

    @mock.patch(
        "sys.argv", ["bandit", "-c", "bandit.yaml", "-s", "badID", "test"]
    )
    def test_main_unknown_skip_tests(self):
        # Test that bandit exits when an invalid test ID is provided to skip
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "wt") as fd:
            fd.write(bandit_config_content)
        # assert a SystemExit with code 2
        self.assertRaisesRegex(SystemExit, "2", bandit.main)

    @mock.patch(
        "sys.argv", ["bandit", "-c", "bandit.yaml", "-p", "bad", "test"]
    )
    def test_main_profile_not_found(self):
        # Test that bandit exits when an invalid profile name is provided
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "wt") as fd:
            fd.write(bandit_config_content)
        # assert a SystemExit with code 2
        with mock.patch("bandit.cli.main.LOG.error") as err_mock:
            self.assertRaisesRegex(SystemExit, "2", bandit.main)
            self.assertEqual(
                str(err_mock.call_args[0][0]),
                "Unable to find profile (bad) in config file: bandit.yaml",
            )

    @mock.patch(
        "sys.argv", ["bandit", "-c", "bandit.yaml", "-b", "base.json", "test"]
    )
    def test_main_baseline_ioerror(self):
        # Test that bandit exits when encountering an IOError while reading
        # baseline data
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "wt") as fd:
            fd.write(bandit_config_content)
        with open("base.json", "wt") as fd:
            fd.write(bandit_baseline_content)
        with mock.patch(
            "bandit.core.manager.BanditManager.populate_baseline"
        ) as mock_mgr_pop_bl:
            mock_mgr_pop_bl.side_effect = IOError
            # assert a SystemExit with code 2
            self.assertRaisesRegex(SystemExit, "2", bandit.main)

    @mock.patch(
        "sys.argv",
        [
            "bandit",
            "-c",
            "bandit.yaml",
            "-b",
            "base.json",
            "-f",
            "csv",
            "test",
        ],
    )
    def test_main_invalid_output_format(self):
        # Test that bandit exits when an invalid output format is selected
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "wt") as fd:
            fd.write(bandit_config_content)
        with open("base.json", "wt") as fd:
            fd.write(bandit_baseline_content)
        # assert a SystemExit with code 2
        self.assertRaisesRegex(SystemExit, "2", bandit.main)

    @mock.patch(
        "sys.argv", ["bandit", "-c", "bandit.yaml", "test", "-o", "output"]
    )
    def test_main_exit_with_results(self):
        # Test that bandit exits when there are results
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "wt") as fd:
            fd.write(bandit_config_content)
        with mock.patch(
            "bandit.core.manager.BanditManager.results_count"
        ) as mock_mgr_results_ct:
            mock_mgr_results_ct.return_value = 1
            # assert a SystemExit with code 1
            self.assertRaisesRegex(SystemExit, "1", bandit.main)

    @mock.patch(
        "sys.argv", ["bandit", "-c", "bandit.yaml", "test", "-o", "output"]
    )
    def test_main_exit_with_no_results(self):
        # Test that bandit exits when there are no results
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "wt") as fd:
            fd.write(bandit_config_content)
        with mock.patch(
            "bandit.core.manager.BanditManager.results_count"
        ) as mock_mgr_results_ct:
            mock_mgr_results_ct.return_value = 0
            # assert a SystemExit with code 0
            self.assertRaisesRegex(SystemExit, "0", bandit.main)

    @mock.patch(
        "sys.argv",
        ["bandit", "-c", "bandit.yaml", "test", "-o", "output", "--exit-zero"],
    )
    def test_main_exit_with_results_and_with_exit_zero_flag(self):
        # Test that bandit exits with 0 on results and zero flag
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "wt") as fd:
            fd.write(bandit_config_content)
        with mock.patch(
            "bandit.core.manager.BanditManager.results_count"
        ) as mock_mgr_results_ct:
            mock_mgr_results_ct.return_value = 1

            self.assertRaisesRegex(SystemExit, "0", bandit.main)
