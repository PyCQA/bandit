from bandit.bandit_config_generator import get_config_settings

import mock
import testtools

import stevedore.extension

class BanditConfigGeneratorTests(testtools.TestCase):
    @mock.patch('stevedore.extension.ExtensionManager',
                spec=stevedore.extension.ExtensionManager)
    @mock.patch('stevedore.extension.Extension',
                spec=stevedore.extension.Extension)
    def test_get_config_settings(self, ext_mgr, ext):
        # TODO(tmcpeak): We need to add unit testing here
        pass