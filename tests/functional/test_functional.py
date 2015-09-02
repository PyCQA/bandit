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

import inspect

import six
import testtools

from bandit.core import constants as C
from bandit.core import manager as b_manager
from bandit.core import test_set as b_test_set


cfg_file = os.path.join(os.getcwd(), 'bandit/config/bandit.yaml')


class FunctionalTests(testtools.TestCase):

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

    def run_example(self, example_script):
        '''A helper method to run the specified test

        This method runs the test, which populates the self.b_mgr.scores
        value. Call this directly if you need to run a test, but do not
        need to test the resulting scores against specified values.
        :param example_script: Filename of an example script to test
        '''
        path = os.path.join(os.getcwd(), 'examples', example_script)
        self.b_mgr.discover_files([path], True)
        self.b_mgr.run_tests()

    def check_example(self, example_script, expect):
        '''A helper method to test the scores for example scripts.

        :param example_script: Filename of an example script to test
        :param expect: dict with expected counts of issue types
        '''
        # reset scores for subsequent calls to check_example
        self.b_mgr.scores = []
        self.run_example(example_script)
        expected = 0
        result = 0
        for test_scores in self.b_mgr.scores:
            for score_type in test_scores:
                self.assertIn(score_type, expect)
                for rating in expect[score_type]:
                    expected += (
                        expect[score_type][rating] * C.RANKING_VALUES[rating]
                    )
                result += sum(test_scores[score_type])
        self.assertEqual(expected, result)

    def test_binding(self):
        '''Test the bind-to-0.0.0.0 example.'''
        expect = {'SEVERITY': {'MEDIUM': 1}, 'CONFIDENCE': {'MEDIUM': 1}}
        self.check_example('binding.py', expect)

    def test_crypto_md5(self):
        '''Test the `hashlib.md5` example.'''
        expect = {'SEVERITY': {'MEDIUM': 8}, 'CONFIDENCE': {'HIGH': 8}}
        self.check_example('crypto-md5.py', expect)

    def test_eval(self):
        '''Test the `eval` example.'''
        expect = {'SEVERITY': {'MEDIUM': 3}, 'CONFIDENCE': {'HIGH': 3}}
        self.check_example('eval.py', expect)

    def test_exec(self):
        '''Test the `exec` example.'''
        filename = 'exec-{}.py'
        if six.PY2:
            filename = filename.format('py2')
            expect = {'SEVERITY': {'MEDIUM': 2}, 'CONFIDENCE': {'HIGH': 2}}
        else:
            filename = filename.format('py3')
            expect = {'SEVERITY': {'MEDIUM': 1}, 'CONFIDENCE': {'HIGH': 1}}
        self.check_example(filename, expect)

    def test_exec_as_root(self):
        '''Test for the `run_as_root=True` keyword argument.'''
        expect = {'SEVERITY': {'LOW': 5}, 'CONFIDENCE': {'MEDIUM': 5}}
        self.check_example('exec-as-root.py', expect)

    def test_hardcoded_passwords(self):
        '''Test for hard-coded passwords.'''
        expect = {'SEVERITY': {'LOW': 2}, 'CONFIDENCE': {'LOW': 2}}
        self.check_example('hardcoded-passwords.py', expect)

    def test_hardcoded_tmp(self):
        '''Test for hard-coded /tmp, /var/tmp, /dev/shm'''
        expect = {'SEVERITY': {'MEDIUM': 3}, 'CONFIDENCE': {'MEDIUM': 3}}
        self.check_example('hardcoded-tmp.py', expect)

    def test_httplib_https(self):
        '''Test for `httplib.HTTPSConnection`.'''
        expect = {'SEVERITY': {'MEDIUM': 1}, 'CONFIDENCE': {'HIGH': 1}}
        self.check_example('httplib_https.py', expect)

    def test_imports_aliases(self):
        '''Test the `import X as Y` syntax.'''
        expect = {
            'SEVERITY': {'LOW': 3, 'MEDIUM': 5, 'HIGH': 1},
            'CONFIDENCE': {'HIGH': 9}
        }
        self.check_example('imports-aliases.py', expect)

    def test_imports_from(self):
        '''Test the `from X import Y` syntax.'''
        expect = {'SEVERITY': {'LOW': 3}, 'CONFIDENCE': {'HIGH': 3}}
        self.check_example('imports-from.py', expect)

    def test_imports_function(self):
        '''Test the `__import__` function.'''
        expect = {'SEVERITY': {'LOW': 2}, 'CONFIDENCE': {'HIGH': 2}}
        self.check_example('imports-function.py', expect)

    def test_imports_telnetlib(self):
        '''Test for `import telnetlib`.'''
        expect = {'SEVERITY': {'HIGH': 1}, 'CONFIDENCE': {'HIGH': 1}}
        self.check_example('imports-telnetlib.py', expect)

    def test_imports(self):
        '''Test for dangerous imports.'''
        expect = {'SEVERITY': {'LOW': 2}, 'CONFIDENCE': {'HIGH': 2}}
        self.check_example('imports.py', expect)

    def test_multiline_str(self):
        '''Test docstrings and multi-line strings are handled properly.'''
        expect = {'SEVERITY': {'MEDIUM': 3}, 'CONFIDENCE': {'MEDIUM': 3}}
        self.check_example('multiline-str.py', expect)

    def test_mktemp(self):
        '''Test for `tempfile.mktemp`.'''
        expect = {'SEVERITY': {'MEDIUM': 4}, 'CONFIDENCE': {'HIGH': 4}}
        self.check_example('mktemp.py', expect)

    def test_nonsense(self):
        '''Test that a syntactically invalid module is skipped.'''
        self.run_example('nonsense.py')
        self.assertEqual(1, len(self.b_mgr.b_rs.skipped))

    def test_okay(self):
        '''Test a vulnerability-free file.'''
        expect = {'SEVERITY': {}, 'CONFIDENCE': {}}
        self.check_example('okay.py', expect)

    def test_os_chmod(self):
        '''Test setting file permissions.'''
        filename = 'os-chmod-{}.py'
        if six.PY2:
            filename = filename.format('py2')
            expect = {
                'SEVERITY': {'MEDIUM': 2, 'HIGH': 9},
                'CONFIDENCE': {'HIGH': 10, 'MEDIUM': 1}
            }
        else:
            filename = filename.format('py3')
            expect = {
                'SEVERITY': {'MEDIUM': 2, 'HIGH': 9},
                'CONFIDENCE': {'HIGH': 10, 'MEDIUM': 1}
            }
        self.check_example('os-chmod.py', expect)

    def test_os_exec(self):
        '''Test for `os.exec*`.'''
        expect = {'SEVERITY': {'LOW': 8}, 'CONFIDENCE': {'MEDIUM': 8}}
        self.check_example('os-exec.py', expect)

    def test_os_popen(self):
        '''Test for `os.popen`.'''
        expect = {'SEVERITY': {'MEDIUM': 7}, 'CONFIDENCE': {'MEDIUM': 7}}
        self.check_example('os-popen.py', expect)

    def test_os_spawn(self):
        '''Test for `os.spawn*`.'''
        expect = {'SEVERITY': {'LOW': 8}, 'CONFIDENCE': {'MEDIUM': 8}}
        self.check_example('os-spawn.py', expect)

    def test_os_startfile(self):
        '''Test for `os.startfile`.'''
        expect = {'SEVERITY': {'LOW': 3}, 'CONFIDENCE': {'MEDIUM': 3}}
        self.check_example('os-startfile.py', expect)

    def test_os_system(self):
        '''Test for `os.system`.'''
        expect = {'SEVERITY': {'MEDIUM': 1}, 'CONFIDENCE': {'MEDIUM': 1}}
        self.check_example('os_system.py', expect)

    def test_pickle(self):
        '''Test for the `pickle` module.'''
        expect = {
            'SEVERITY': {'LOW': 2, 'MEDIUM': 6},
            'CONFIDENCE': {'HIGH': 8 }
        }
        self.check_example('pickle_deserialize.py', expect)

    def test_popen_wrappers(self):
        '''Test the `popen2` and `commands` modules.'''
        expect = {'SEVERITY': {'MEDIUM': 7}, 'CONFIDENCE': {'MEDIUM': 7}}
        self.check_example('popen_wrappers.py', expect)

    def test_random_module(self):
        '''Test for the `random` module.'''
        expect = {'SEVERITY': {'LOW': 6}, 'CONFIDENCE': {'HIGH': 6}}
        self.check_example('random_module.py', expect)

    def test_requests_ssl_verify_disabled(self):
        '''Test for the `requests` library skipping verification.'''
        expect = {'SEVERITY': {'HIGH': 2}, 'CONFIDENCE': {'HIGH': 2}}
        self.check_example('requests-ssl-verify-disabled.py', expect)

    def test_skip(self):
        '''Test `#nosec` and `#noqa` comments.'''
        expect = {'SEVERITY': {'LOW': 5}, 'CONFIDENCE': {'HIGH': 5}}
        self.check_example('skip.py', expect)

    def test_sql_statements(self):
        '''Test for SQL injection through string building.'''
        expect = {
            'SEVERITY': {'MEDIUM': 11},
            'CONFIDENCE': {'LOW': 6, 'MEDIUM': 5}}
        self.check_example('sql_statements.py', expect)

    def test_ssl_insecure_version(self):
        '''Test for insecure SSL protocol versions.'''
        expect = {
            'SEVERITY': {'LOW': 1, 'MEDIUM': 10, 'HIGH': 7},
            'CONFIDENCE': {'LOW': 0, 'MEDIUM': 11, 'HIGH': 7}
        }
        self.check_example('ssl-insecure-version.py', expect)

    def test_subprocess_shell(self):
        '''Test for `subprocess.Popen` with `shell=True`.'''
        expect = {
            'SEVERITY': {'HIGH': 5, 'MEDIUM': 1, 'LOW': 7},
            'CONFIDENCE': {'HIGH': 13}
        }
        self.check_example('subprocess_shell.py', expect)

    def test_urlopen(self):
        '''Test for dangerous URL opening.'''
        expect = {'SEVERITY': {'MEDIUM': 6}, 'CONFIDENCE': {'HIGH': 6}}
        self.check_example('urlopen.py', expect)

    def test_utils_shell(self):
        '''Test for `utils.execute*` with `shell=True`.'''
        expect = {
            'SEVERITY': {'HIGH': 4, 'LOW': 1},
            'CONFIDENCE': {'HIGH': 5}
        }
        self.check_example('utils-shell.py', expect)

    def test_wildcard_injection(self):
        '''Test for wildcard injection in shell commands.'''
        expect = {
            'SEVERITY': {'HIGH': 5, 'MEDIUM':3, 'LOW': 6},
            'CONFIDENCE': {'MEDIUM': 8, 'HIGH': 6}
        }
        self.check_example('wildcard-injection.py', expect)

    def test_yaml(self):
        '''Test for `yaml.load`.'''
        expect = {'SEVERITY': {'MEDIUM': 1}, 'CONFIDENCE': {'HIGH': 1}}
        self.check_example('yaml_load.py', expect)

    def test_jinja2_templating(self):
        '''Test jinja templating for potential XSS bugs.'''
        expect = {
            'SEVERITY': {'HIGH': 4},
            'CONFIDENCE': {'HIGH': 3, 'MEDIUM':1}
        }
        self.check_example('jinja2_templating.py', expect)

    def test_secret_config_option(self):
        '''Test for `secret=True` in Oslo's config.'''
        expect = {
            'SEVERITY': {'LOW': 1, 'MEDIUM': 2},
            'CONFIDENCE': {'MEDIUM': 3}
        }
        self.check_example('secret-config-option.py', expect)

    def test_mako_templating(self):
        '''Test Mako templates for XSS.'''
        expect = {'SEVERITY': {'MEDIUM': 3}, 'CONFIDENCE': {'HIGH': 3}}
        self.check_example('mako_templating.py', expect)

    def test_xml(self):
        '''Test xml vulnerabilities.'''
        expect = {'SEVERITY': {'LOW': 1, 'HIGH': 4},
                  'CONFIDENCE': {'HIGH': 1, 'MEDIUM': 4}}
        self.check_example('xml_etree_celementtree.py', expect)

        expect = {'SEVERITY': {'LOW': 1, 'HIGH': 2},
                  'CONFIDENCE': {'HIGH': 1, 'MEDIUM': 2}}
        self.check_example('xml_expatbuilder.py', expect)

        expect = {'SEVERITY': {'LOW': 3, 'HIGH': 1},
                  'CONFIDENCE': {'HIGH': 3, 'MEDIUM': 1}}
        self.check_example('xml_lxml.py', expect)

        expect = {'SEVERITY': {'LOW': 2, 'HIGH': 2},
                  'CONFIDENCE': {'HIGH': 2, 'MEDIUM': 2}}
        self.check_example('xml_pulldom.py', expect)

        expect = {'SEVERITY': {'HIGH': 1},
                  'CONFIDENCE': {'HIGH': 1}}
        self.check_example('xml_xmlrpc.py', expect)

        expect = {'SEVERITY': {'LOW': 1, 'HIGH': 4},
                  'CONFIDENCE': {'HIGH': 1, 'MEDIUM': 4}}
        self.check_example('xml_etree_elementtree.py', expect)

        expect = {'SEVERITY': {'LOW': 1, 'HIGH': 1},
                  'CONFIDENCE': {'HIGH': 1, 'MEDIUM': 1}}
        self.check_example('xml_expatreader.py', expect)

        expect = {'SEVERITY': {'LOW': 2, 'HIGH': 2},
                  'CONFIDENCE': {'HIGH': 2, 'MEDIUM': 2}}
        self.check_example('xml_minidom.py', expect)

        expect = {'SEVERITY': {'LOW': 1, 'HIGH': 6},
                  'CONFIDENCE': {'HIGH': 1, 'MEDIUM': 6}}
        self.check_example('xml_sax.py', expect)

    def test_asserts(self):
        '''Test catching the use of assert.'''
        expect = {'SEVERITY': {'LOW': 1},
                  'CONFIDENCE': {'HIGH': 1}}
        self.check_example('assert.py', expect)

    def test_paramiko_injection(self):
        '''Test paramiko command execution.'''
        expect = {'SEVERITY': {'MEDIUM': 2},
                  'CONFIDENCE': {'MEDIUM': 2}}
        self.check_example('paramiko_injection.py', expect)

    def test_partial_path(self):
        '''Test process spawning with partial file paths.'''
        expect = {'SEVERITY': {'LOW': 9},
                  'CONFIDENCE': {'HIGH': 9}}

        self.check_example('partial_path_process.py', expect)

    def test_try_except_pass(self):
        '''Test try, except pass detection.'''
        expect = {'SEVERITY': {'LOW': 3},
                  'CONFIDENCE': {'HIGH': 3}}

        self.check_example('try_except_pass.py', expect)

    def test_multiline_code(self):
        '''Test issues in multiline statements return code as expected.'''
        self.run_example('multiline-str.py')
        self.assertEqual(0, len(self.b_mgr.b_rs.skipped))
        self.assertEqual(1, len(self.b_mgr.files_list))
        self.assertTrue(self.b_mgr.files_list[0].endswith('multiline-str.py'))
        issues = self.b_mgr.b_rs._get_issue_list()
        self.assertEqual(3, len(issues))
        self.assertTrue(
            issues[0]['filename'].endswith('examples/multiline-str.py')
        )
        self.assertEqual(4, issues[0]['line_number'])
        self.assertEqual(range(2, 7), issues[0]['line_range'])
        self.assertIn('/tmp', issues[0]['code'])
        self.assertEqual(18, issues[1]['line_number'])
        self.assertEqual(range(16, 19), issues[1]['line_range'])
        self.assertIn('/tmp', issues[1]['code'])
        self.assertEqual(23, issues[2]['line_number'])
        self.assertEqual(range(22, 31), issues[2]['line_range'])
        self.assertIn('/tmp', issues[2]['code'])
