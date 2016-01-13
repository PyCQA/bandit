import fixtures
import os

import appdirs
import testtools

from bandit.cli import main as bandit
from bandit.core import utils

BASE_CONFIG = '/bandit.yaml'


class FindConfigTests(testtools.TestCase):

    def _test(self, directory_with_config=None, user_config_dir=None,
              site_config_dir=None):

        user_config_dir = user_config_dir or self.getUniqueString()
        site_config_dir = site_config_dir or self.getUniqueString()

        self.useFixture(
            fixtures.MockPatch('appdirs.user_config_dir',
                               return_value=user_config_dir))
        self.useFixture(
            fixtures.MockPatch('appdirs.site_config_dir',
                               return_value=site_config_dir))

        def is_current_config(arg):
            if not directory_with_config:
                return False
            return arg == (directory_with_config + BASE_CONFIG)

        self.useFixture(
            fixtures.MockPatch('os.path.isfile', is_current_config))

        found_config = bandit._find_config()
        exp_config = directory_with_config + BASE_CONFIG
        self.assertEqual(exp_config, found_config)

    def test_current_directory(self):
        # the config file in the current directory is returned if it's there.
        self._test(directory_with_config='.')

    def test_user_home_directory(self):
        # the config file in the user home directory is returned if there isn't
        # one in the current directory.
        user_config_dir = self.getUniqueString()
        self._test(directory_with_config=user_config_dir,
                   user_config_dir=user_config_dir)

    def test_bundled_config(self):
        # the bundled config file is returned if there isn't one in the current
        # directory or user home directory.
        site_config_dir = self.getUniqueString()
        self._test(directory_with_config=site_config_dir,
                   site_config_dir=site_config_dir)

    def test_mac_pip_cfg_path(self):
        # pip on Mac installs to /usr/local/etc/bandit/bandit.yaml and that's
        # checked, too. See issue at http://git.io/vOreU
        self._test(directory_with_config='/usr/local/etc/bandit')

    def test_not_found(self):
        # NoConfigFileFound is raised if there's no config in any location.
        self.assertRaises(utils.NoConfigFileFound, self._test)

    def test_bundled_config_split(self):
        # the bundled config can return a path separated by : and all those
        # paths are searched in order.
        dirs = [self.getUniqueString(), self.getUniqueString()]
        site_config_dirs = ':'.join(dirs)

        # Check all the directories
        for dir in dirs:
            self._test(directory_with_config=dir,
                       site_config_dir=site_config_dirs)
