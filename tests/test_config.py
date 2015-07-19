import fixtures
import logging
import mock
import os
import unittest

from appdirs import site_config_dir
from appdirs import user_config_dir

from bandit import bandit
from bandit.core import utils

BASE_CONFIG = '/bandit.yaml'


class ConfigTests(fixtures.TestWithFixtures):

    def is_current_config(self, arg):
        return arg == self.current_config

    def setUp(self):
        super(ConfigTests, self).setUp()
        self.useFixture(fixtures.EnvironmentVariable('XDG_CONFIG_DIRS', '/etc:/usr/local/etc'))
        # Mock os.path.isfile with one that selectively returns
        # True if location being considered is the present one.
        patcher = mock.patch('os.path.isfile', side_effect=self.is_current_config)
        self.mocked_isfile = patcher.start()
        self.addCleanup(patcher.stop)

    def test_find_configs(self):
        #TODO(Daviey): Mock user_config_dir to make input deterministic
        # and test multi-platform locations.
        config_dirs = (['.'] + [user_config_dir("bandit")] +
                       site_config_dir("bandit", multipath=True).split(':'))
        config_locations = [s + BASE_CONFIG for s in config_dirs]

        # check that at least 3 location paths were generated
        self.assertLess(3, len(config_locations))

        # Iterate through found locations
        for c in config_locations:
            self.current_config = c
            ret = bandit._find_config()
            self.assertEquals(self.current_config, ret)

    def test_cannot_find_configs(self):
        self.current_config = "/invalid/file"
        with self.assertRaises(utils.NoConfigFileFound):
            bandit._find_config()
