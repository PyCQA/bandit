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

import six
import testtools

from bandit.core import config as b_config
from bandit.core import constants as C
from bandit.core import manager as b_manager
from bandit.core import metrics
from bandit.core import test_set as b_test_set


cfg_file = os.path.join(os.getcwd(), 'bandit/config/bandit.yaml')


class FunctionalTests(testtools.TestCase):

    '''Functional tests for bandit test plugins.

    This set of tests runs bandit against each example file in turn
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
        b_conf = b_config.BanditConfig(cfg_file)
        self.b_mgr = b_manager.BanditManager(b_conf, 'file')
        self.b_mgr.b_conf._settings['plugins_dir'] = path
        self.b_mgr.b_ts = b_test_set.BanditTestSet(config=b_conf)

    def run_example(self, example_script, ignore_nosec=False):
        '''A helper method to run the specified test

        This method runs the test, which populates the self.b_mgr.scores
        value. Call this directly if you need to run a test, but do not
        need to test the resulting scores against specified values.
        :param example_script: Filename of an example script to test
        '''
        path = os.path.join(os.getcwd(), 'examples', example_script)
        self.b_mgr.ignore_nosec = ignore_nosec
        self.b_mgr.discover_files([path], True)
        self.b_mgr.run_tests()

    def check_example(self, example_script, expect, ignore_nosec=False):
        '''A helper method to test the scores for example scripts.

        :param example_script: Filename of an example script to test
        :param expect: dict with expected counts of issue types
        '''
        # reset scores for subsequent calls to check_example
        self.b_mgr.scores = []
        self.run_example(example_script, ignore_nosec=ignore_nosec)
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

    def check_metrics(self, example_script, expect):
        '''A helper method to test the metrics being returned.

        :param example_script: Filename of an example script to test
        :param expect: dict with expected values of metrics
        '''
        self.b_mgr.metrics = metrics.Metrics()
        self.b_mgr.scores = []
        self.run_example(example_script)

        # test general metrics (excludes issue counts)
        m = self.b_mgr.metrics.data
        for k in expect:
            if k != 'issues':
                self.assertEqual(expect[k], m['_totals'][k])
        # test issue counts
        if 'issues' in expect:
            for (criteria, default) in C.CRITERIA:
                for rank in C.RANKING:
                    label = '{0}.{1}'.format(criteria, rank)
                    expected = 0
                    if expect['issues'].get(criteria, None).get(rank, None):
                        expected = expect['issues'][criteria][rank]
                    self.assertEqual(expected, m['_totals'][label])

    def test_binding(self):
        '''Test the bind-to-0.0.0.0 example.'''
        expect = {'SEVERITY': {'MEDIUM': 1}, 'CONFIDENCE': {'MEDIUM': 1}}
        self.check_example('binding.py', expect)

    def test_crypto_md5(self):
        '''Test the `hashlib.md5` example.'''
        expect = {'SEVERITY': {'MEDIUM': 8}, 'CONFIDENCE': {'HIGH': 8}}
        self.check_example('crypto-md5.py', expect)

    def test_ciphers(self):
        '''Test the `Crypto.Cipher` example.'''
        expect = {'SEVERITY': {'LOW': 1, 'HIGH': 8}, 'CONFIDENCE': {'HIGH': 9}}
        self.check_example('ciphers.py', expect)

    def test_cipher_modes(self):
        '''Test for insecure cipher modes.'''
        expect = {'SEVERITY': {'MEDIUM': 1}, 'CONFIDENCE': {'HIGH': 1}}
        self.check_example('cipher-modes.py', expect)

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
        expect = {'SEVERITY': {'LOW': 7}, 'CONFIDENCE': {'MEDIUM': 7}}
        self.check_example('hardcoded-passwords.py', expect)

    def test_hardcoded_tmp(self):
        '''Test for hard-coded /tmp, /var/tmp, /dev/shm.'''
        expect = {'SEVERITY': {'MEDIUM': 3}, 'CONFIDENCE': {'MEDIUM': 3}}
        self.check_example('hardcoded-tmp.py', expect)

    def test_httplib_https(self):
        '''Test for `httplib.HTTPSConnection`.'''
        expect = {'SEVERITY': {'MEDIUM': 3}, 'CONFIDENCE': {'HIGH': 3}}
        self.check_example('httplib_https.py', expect)

    def test_imports_aliases(self):
        '''Test the `import X as Y` syntax.'''
        expect = {
            'SEVERITY': {'LOW': 4, 'MEDIUM': 5, 'HIGH': 0},
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

    def test_telnet_usage(self):
        '''Test for `import telnetlib` and Telnet.* calls.'''
        expect = {'SEVERITY': {'HIGH': 2}, 'CONFIDENCE': {'HIGH': 2}}
        self.check_example('telnetlib.py', expect)

    def test_imports(self):
        '''Test for dangerous imports.'''
        expect = {'SEVERITY': {'LOW': 2}, 'CONFIDENCE': {'HIGH': 2}}
        self.check_example('imports.py', expect)

    def test_mktemp(self):
        '''Test for `tempfile.mktemp`.'''
        expect = {'SEVERITY': {'MEDIUM': 4}, 'CONFIDENCE': {'HIGH': 4}}
        self.check_example('mktemp.py', expect)

    def test_nonsense(self):
        '''Test that a syntactically invalid module is skipped.'''
        self.run_example('nonsense.py')
        self.assertEqual(1, len(self.b_mgr.skipped))

    def test_okay(self):
        '''Test a vulnerability-free file.'''
        expect = {'SEVERITY': {}, 'CONFIDENCE': {}}
        self.check_example('okay.py', expect)

    def test_os_chmod(self):
        '''Test setting file permissions.'''
        filename = 'os-chmod-{}.py'
        if six.PY2:
            filename = filename.format('py2')
        else:
            filename = filename.format('py3')
        expect = {
            'SEVERITY': {'MEDIUM': 2, 'HIGH': 8},
            'CONFIDENCE': {'MEDIUM': 1, 'HIGH': 9}
        }
        self.check_example(filename, expect)

    def test_os_exec(self):
        '''Test for `os.exec*`.'''
        expect = {'SEVERITY': {'LOW': 8}, 'CONFIDENCE': {'MEDIUM': 8}}
        self.check_example('os-exec.py', expect)

    def test_os_popen(self):
        '''Test for `os.popen`.'''
        expect = {'SEVERITY': {'LOW': 7, 'MEDIUM': 1, 'HIGH': 1},
                  'CONFIDENCE': {'HIGH': 9}}
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
        expect = {'SEVERITY': {'LOW': 1}, 'CONFIDENCE': {'HIGH': 1}}
        self.check_example('os_system.py', expect)

    def test_pickle(self):
        '''Test for the `pickle` module.'''
        expect = {
            'SEVERITY': {'LOW': 2, 'MEDIUM': 6},
            'CONFIDENCE': {'HIGH': 8}
        }
        self.check_example('pickle_deserialize.py', expect)

    def test_popen_wrappers(self):
        '''Test the `popen2` and `commands` modules.'''
        expect = {'SEVERITY': {'MEDIUM': 7}, 'CONFIDENCE': {'HIGH': 7}}
        self.check_example('popen_wrappers.py', expect)

    def test_random_module(self):
        '''Test for the `random` module.'''
        expect = {'SEVERITY': {'LOW': 6}, 'CONFIDENCE': {'HIGH': 6}}
        self.check_example('random_module.py', expect)

    def test_requests_ssl_verify_disabled(self):
        '''Test for the `requests` library skipping verification.'''
        expect = {'SEVERITY': {'HIGH': 7}, 'CONFIDENCE': {'HIGH': 7}}
        self.check_example('requests-ssl-verify-disabled.py', expect)

    def test_skip(self):
        '''Test `#nosec` and `#noqa` comments.'''
        expect = {'SEVERITY': {'LOW': 5}, 'CONFIDENCE': {'HIGH': 5}}
        self.check_example('skip.py', expect)

    def test_ignore_skip(self):
        '''Test --ignore-nosec flag.'''
        expect = {'SEVERITY': {'LOW': 7}, 'CONFIDENCE': {'HIGH': 7}}
        self.check_example('skip.py', expect, ignore_nosec=True)

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
            'SEVERITY': {'HIGH': 3, 'MEDIUM': 2, 'LOW': 12},
            'CONFIDENCE': {'HIGH': 16, 'LOW': 1}
        }
        self.check_example('subprocess_shell.py', expect)

    def test_urlopen(self):
        '''Test for dangerous URL opening.'''
        expect = {'SEVERITY': {'MEDIUM': 14}, 'CONFIDENCE': {'HIGH': 14}}
        self.check_example('urlopen.py', expect)

    def test_utils_shell(self):
        '''Test for `utils.execute*` with `shell=True`.'''
        expect = {
            'SEVERITY': {'LOW': 5},
            'CONFIDENCE': {'HIGH': 5}
        }
        self.check_example('utils-shell.py', expect)

    def test_wildcard_injection(self):
        '''Test for wildcard injection in shell commands.'''
        expect = {
            'SEVERITY': {'HIGH': 4, 'MEDIUM': 4, 'LOW': 6},
            'CONFIDENCE': {'MEDIUM': 5, 'HIGH': 9}
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
            'CONFIDENCE': {'HIGH': 3, 'MEDIUM': 1}
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

        test = self.b_mgr.b_ts.tests['ExceptHandler']['try_except_pass']
        test._config = {'check_typed_exception': False}
        expect = {'SEVERITY': {'LOW': 2},
                  'CONFIDENCE': {'HIGH': 2}}

        self.check_example('try_except_pass.py', expect)

    def test_metric_gathering(self):
        expect = {
            'nosec': 2, 'loc': 7,
            'issues': {'CONFIDENCE': {'HIGH': 5}, 'SEVERITY': {'LOW': 5}}
        }
        self.check_metrics('skip.py', expect)
        expect = {
            'nosec': 0, 'loc': 4,
            'issues': {'CONFIDENCE': {'HIGH': 2}, 'SEVERITY': {'LOW': 2}}
        }
        self.check_metrics('imports.py', expect)

    def test_weak_cryptographic_key(self):
        '''Test for weak key sizes.'''
        expect = {
            'SEVERITY': {'MEDIUM': 5, 'HIGH': 4},
            'CONFIDENCE': {'HIGH': 9}
        }
        self.check_example('weak_cryptographic_key_sizes.py', expect)

    def test_multiline_code(self):
        '''Test issues in multiline statements return code as expected.'''
        self.run_example('multiline_statement.py')
        self.assertEqual(0, len(self.b_mgr.skipped))
        self.assertEqual(1, len(self.b_mgr.files_list))
        self.assertTrue(self.b_mgr.files_list[0].endswith(
                        'multiline_statement.py'))

        issues = self.b_mgr.get_issue_list()
        self.assertEqual(2, len(issues))
        self.assertTrue(
            issues[0].fname.endswith('examples/multiline_statement.py')
        )

        self.assertEqual(1, issues[0].lineno)
        self.assertEqual(list(range(1, 3)), issues[0].linerange)
        self.assertIn('subprocess', issues[0].get_code())
        self.assertEqual(5, issues[1].lineno)
        self.assertEqual(list(range(3, 6 + 1)), issues[1].linerange)
        self.assertIn('shell=True', issues[1].get_code())

    def test_code_line_numbers(self):
        self.run_example('binding.py')
        issues = self.b_mgr.get_issue_list()

        code_lines = issues[0].get_code().splitlines()
        lineno = issues[0].lineno
        self.assertEqual("%i " % (lineno - 1), code_lines[0][:2])
        self.assertEqual("%i " % (lineno), code_lines[1][:2])
        self.assertEqual("%i " % (lineno + 1), code_lines[2][:2])

    def test_flask_debug_true(self):
        expect = {
            'SEVERITY': {'HIGH': 1},
            'CONFIDENCE': {'MEDIUM': 1}
        }
        self.check_example('flask_debug.py', expect)

    def test_nosec(self):
        expect = {
            'SEVERITY': {},
            'CONFIDENCE': {}
        }
        self.check_example('nosec.py', expect)

    def test_baseline_filter(self):
        issue_text = ('A Flask app appears to be run with debug=True, which '
                      'exposes the Werkzeug debugger and allows the execution '
                      'of arbitrary code.')
        json = """{
          "results": [
            {
              "code": "...",
              "filename": "%s/examples/flask_debug.py",
              "issue_confidence": "MEDIUM",
              "issue_severity": "HIGH",
              "issue_text": "%s",
              "line_number": 10,
              "line_range": [
                10
              ],
              "test_name": "flask_debug_true",
              "test_id": "B201"
            }
          ]
        }
        """ % (os.getcwd(), issue_text)

        self.b_mgr.populate_baseline(json)
        self.run_example('flask_debug.py')
        self.assertEqual(len(self.b_mgr.baseline), 1)
        self.assertEqual(self.b_mgr.get_issue_list(), {})
