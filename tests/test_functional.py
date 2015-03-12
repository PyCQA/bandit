# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
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

import unittest
import inspect

from bandit.core import constants as C
from bandit.core import manager as b_manager
from bandit.core import test_set as b_test_set


cfg_file = os.path.join(os.getcwd(), 'bandit.yaml')


class FunctionalTests(unittest.TestCase):

    '''This set of tests runs bandit against each example file in turn
    and records the score returned. This is compared to a known good value.
    When new tests are added to an example the expected result should be
    adjusted to match.
    '''

    def setUp(self):
        super(FunctionalTests, self).setUp()
        # NOTE(tkelsey): bandit is very sensitive to paths, so stitch
        # them up here for the testing environment.
        #
        path = os.path.join(os.getcwd(), 'bandit', 'plugins')
        self.b_mgr = b_manager.BanditManager(cfg_file, 'file')
        self.b_mgr.b_conf._settings['plugins_dir'] = path
        self.b_mgr.b_ts = b_test_set.BanditTestSet(self.b_mgr.logger,
                                                   config=self.b_mgr.b_conf,
                                                   profile=None)

    def tearDown(self):
        pass

    def check_example(self, example_script, info=0, warn=0, error=0):
        '''A helper method to test the scores for example scripts.

        :param example_script: Filename of an example script to test
        :param info: The expected number of INFO-level issues to find
        :param warn: The expected number of WARN-level issues to find
        :param error: The expected number of ERROR-level issues to find
        '''
        path = os.path.join(os.getcwd(), 'examples', example_script)
        self.b_mgr.discover_files([path], True)
        self.b_mgr.run_tests()
        expected = (info * C.SEVERITY_VALUES['INFO'] +
                    warn * C.SEVERITY_VALUES['WARN'] +
                    error * C.SEVERITY_VALUES['ERROR'])
        self.assertEqual(expected, self.b_mgr.scores[0])

    def test_binding(self):
        '''Test the bind-to-0.0.0.0 example.'''
        self.check_example('binding.py', warn=1)

    def test_crypto_md5(self):
        '''Test the `hashlib.md5` example.'''
        self.check_example('crypto-md5.py', warn=5)

    def test_eval(self):
        '''Test the `eval` example.'''
        self.check_example('eval.py', warn=3)

    def test_exec(self):
        '''Test the `exec` example.'''
        self.check_example('exec.py', error=2)

    def test_exec_as_root(self):
        '''Test for the `run_as_root=True` keyword argument.'''
        self.check_example('exec-as-root.py', info=5)

    def test_hardcoded_passwords(self):
        '''Test for hard-coded passwords.'''
        self.check_example('hardcoded-passwords.py', info=2)

    def test_hardcoded_tmp(self):
        '''Test for hard-coded /tmp.'''
        self.check_example('hardcoded-tmp.py', warn=1)

    def test_httplib_https(self):
        '''Test for `httplib.HTTPSConnection`.'''
        self.check_example('httplib_https.py', warn=1)

    def test_imports_aliases(self):
        '''Test the `import X as Y` syntax.'''
        self.check_example('imports-aliases.py', info=3, warn=5, error=1)

    def test_imports_from(self):
        '''Test the `from X import Y` syntax.'''
        self.check_example('imports-from.py', info=3)

    def test_imports_function(self):
        '''Test the `__import__` function.'''
        self.check_example('imports-function.py', info=2)

    def test_imports_telnetlib(self):
        '''Test for `import telnetlib`.'''
        self.check_example('imports-telnetlib.py', error=1)

    def test_imports(self):
        '''Test for dangerous imports.'''
        self.check_example('imports.py', info=2)

    def test_mktemp(self):
        '''Test for `tempfile.mktemp`.'''
        self.check_example('mktemp.py', warn=4)

    def test_nonsense(self):
        '''Test that a syntactically invalid module is skipped.'''
        self.check_example('nonsense.py')
        self.assertEqual(1, len(self.b_mgr.b_rs.skipped))

    def test_okay(self):
        '''Test a vulnerability-free file.'''
        self.check_example('okay.py')

    def test_os_chmod(self):
        '''Test setting file permissions.'''
        self.check_example('os-chmod.py', warn=1, error=8)

    def test_os_exec(self):
        '''Test for `os.exec*`.'''
        self.check_example('os-exec.py', info=8)

    def test_os_popen(self):
        '''Test for `os.popen`.'''
        self.check_example('os-popen.py', error=7)

    def test_os_spawn(self):
        '''Test for `os.spawn*`.'''
        self.check_example('os-spawn.py', info=8)

    def test_os_startfile(self):
        '''Test for `os.startfile`.'''
        self.check_example('os-startfile.py', info=3)

    def test_os_system(self):
        '''Test for `os.system`.'''
        self.check_example('os_system.py', error=1)

    def test_pickle(self):
        '''Test for the `pickle` module.'''
        self.check_example('pickle_deserialize.py', info=2, warn=6)

    def test_popen_wrappers(self):
        '''Test the `popen2` and `commands` modules.'''
        self.check_example('popen_wrappers.py', error=7)

    def test_random_module(self):
        '''Test for the `random` module.'''
        self.check_example('random_module.py', info=3)

    def test_requests_ssl_verify_disabled(self):
        '''Test for the `requests` library skipping verification.'''
        self.check_example('requests-ssl-verify-disabled.py', error=2)

    @unittest.skip('#nosec lines are scored, but do not appear in the report')
    def test_skip(self):
        '''Test `#nosec` and `#noqa` comments.'''
        self.check_example('skip.py', warn=5)

    def test_sql_statements_with_sqlalchemy(self):
        '''Test for SQL injection through string building.'''
        self.check_example('sql_statements_with_sqlalchemy.py', info=4)

    def test_sql_statements_without_sql_alchemy(self):
        '''Test for SQL injection without SQLAlchemy.'''
        self.check_example('sql_statements_without_sql_alchemy.py', warn=4)

    def test_ssl_insecure_version(self):
        '''Test for insecure SSL protocol versions.'''
        self.check_example('ssl-insecure-version.py', info=1, warn=10, error=7)

    def test_subprocess_shell(self):
        '''Test for `subprocess.Popen` with `shell=True`.'''
        self.check_example('subprocess_shell.py', info=7, warn=1, error=5)

    def test_urlopen(self):
        '''Test for dangerous URL opening.'''
        self.check_example('urlopen.py', warn=6)

    def test_utils_shell(self):
        '''Test for `utils.execute*` with `shell=True`.'''
        self.check_example('utils-shell.py', info=1, error=4)

    def test_wildcard_injection(self):
        '''Test for wildcard injection in shell commands.'''
        self.check_example('wildcard-injection.py', info=6, error=8)

    def test_yaml(self):
        '''Test for `yaml.load`.'''
        self.check_example('yaml_load.py', warn=1)

    def test_jinja2_templating(self):
        '''Test jinja templating for potential XSS bugs.'''
        self.check_example('jinja2_templating.py', warn=1, error=3)

    def test_secret_config_option(self):
        '''Test for `secret=True` in Oslo's config.'''
        self.check_example('secret-config-option.py', info=1, warn=2)

    def test_mako_templating(self):
        '''Test Mako templates for XSS.'''
        self.check_example('mako_templating.py', warn=3)
