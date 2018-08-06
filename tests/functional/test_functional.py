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
        b_conf = b_config.BanditConfig()
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

        result = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
        }

        for test_scores in self.b_mgr.scores:
            for score_type in test_scores:
                self.assertIn(score_type, expect)
                for idx, rank in enumerate(C.RANKING):
                    result[score_type][rank] = (test_scores[score_type][idx] //
                                                C.RANKING_VALUES[rank])

        self.assertDictEqual(expect, result)

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
                    if expect['issues'].get(criteria).get(rank):
                        expected = expect['issues'][criteria][rank]
                    self.assertEqual(expected, m['_totals'][label])

    def test_binding(self):
        '''Test the bind-to-0.0.0.0 example.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 1, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 1, 'HIGH': 0}
        }
        self.check_example('binding.py', expect)

    def test_crypto_md5(self):
        '''Test the `hashlib.md5` example.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 15, 'HIGH': 8},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 23}
        }
        self.check_example('crypto-md5.py', expect)

    def test_ciphers(self):
        '''Test the `Crypto.Cipher` example.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 1, 'HIGH': 26},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 27}
        }
        self.check_example('ciphers.py', expect)

    def test_cipher_modes(self):
        '''Test for insecure cipher modes.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 1, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 1}
        }
        self.check_example('cipher-modes.py', expect)

    def test_eval(self):
        '''Test the `eval` example.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 3, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 3}
        }
        self.check_example('eval.py', expect)

    def test_mark_safe(self):
        '''Test the `mark_safe` example.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 1, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 1}
        }
        self.check_example('mark_safe.py', expect)

    def test_exec(self):
        '''Test the `exec` example.'''
        filename = 'exec-{}.py'
        if six.PY2:
            filename = filename.format('py2')
            expect = {
                'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 2, 'HIGH': 0},
                'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0,
                               'HIGH': 2}
            }
        else:
            filename = filename.format('py3')
            expect = {
                'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 1, 'HIGH': 0},
                'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0,
                               'HIGH': 1}
            }
        self.check_example(filename, expect)

    def test_hardcoded_passwords(self):
        '''Test for hard-coded passwords.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 8, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 8, 'HIGH': 0}
        }
        self.check_example('hardcoded-passwords.py', expect)

    def test_hardcoded_tmp(self):
        '''Test for hard-coded /tmp, /var/tmp, /dev/shm.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 3, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 3, 'HIGH': 0}
        }
        self.check_example('hardcoded-tmp.py', expect)

    def test_httplib_https(self):
        '''Test for `httplib.HTTPSConnection`.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 3, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 3}
        }
        self.check_example('httplib_https.py', expect)

    def test_imports_aliases(self):
        '''Test the `import X as Y` syntax.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 4, 'MEDIUM': 5, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 9}
        }
        self.check_example('imports-aliases.py', expect)

    def test_imports_from(self):
        '''Test the `from X import Y` syntax.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 3, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 3}
        }
        self.check_example('imports-from.py', expect)

    def test_imports_function(self):
        '''Test the `__import__` function.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 2, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2}
        }
        self.check_example('imports-function.py', expect)

    def test_telnet_usage(self):
        '''Test for `import telnetlib` and Telnet.* calls.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2}
        }
        self.check_example('telnetlib.py', expect)

    def test_ftp_usage(self):
        '''Test for `import ftplib` and FTP.* calls.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2}
        }
        self.check_example('ftplib.py', expect)

    def test_imports(self):
        '''Test for dangerous imports.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 2, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2}
        }
        self.check_example('imports.py', expect)

    def test_imports_using_importlib(self):
        '''Test for dangerous imports using importlib.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 2, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2}
        }
        self.check_example('imports-with-importlib.py', expect)

    def test_mktemp(self):
        '''Test for `tempfile.mktemp`.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 4, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 4}
        }
        self.check_example('mktemp.py', expect)

    def test_tempnam(self):
        '''Test for `os.tempnam` / `os.tmpnam`.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 6, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 6}
        }
        self.check_example('tempnam.py', expect)

    def test_nonsense(self):
        '''Test that a syntactically invalid module is skipped.'''
        self.run_example('nonsense.py')
        self.assertEqual(1, len(self.b_mgr.skipped))

    def test_okay(self):
        '''Test a vulnerability-free file.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
        }
        self.check_example('okay.py', expect)

    def test_subdirectory_okay(self):
        '''Test a vulnerability-free file under a subdirectory.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
        }
        self.check_example('init-py-test/subdirectory-okay.py', expect)

    def test_os_chmod(self):
        '''Test setting file permissions.'''
        filename = 'os-chmod-{}.py'
        if six.PY2:
            filename = filename.format('py2')
        else:
            filename = filename.format('py3')
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 2, 'HIGH': 8},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 1, 'HIGH': 9}
        }
        self.check_example(filename, expect)

    def test_os_exec(self):
        '''Test for `os.exec*`.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 8, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 8, 'HIGH': 0}
        }
        self.check_example('os-exec.py', expect)

    def test_os_popen(self):
        '''Test for `os.popen`.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 8, 'MEDIUM': 0, 'HIGH': 1},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 9}
        }
        self.check_example('os-popen.py', expect)

    def test_os_spawn(self):
        '''Test for `os.spawn*`.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 8, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 8, 'HIGH': 0}
        }
        self.check_example('os-spawn.py', expect)

    def test_os_startfile(self):
        '''Test for `os.startfile`.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 3, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 3, 'HIGH': 0}
        }
        self.check_example('os-startfile.py', expect)

    def test_os_system(self):
        '''Test for `os.system`.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 1, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 1}
        }
        self.check_example('os_system.py', expect)

    def test_pickle(self):
        '''Test for the `pickle` module.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 2, 'MEDIUM': 6, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 8}
        }
        self.check_example('pickle_deserialize.py', expect)

    def test_dill(self):
        '''Test for the `dill` module.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 3}
        }
        self.check_example('dill.py', expect)

    def test_popen_wrappers(self):
        '''Test the `popen2` and `commands` modules.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 7, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 7}
        }
        self.check_example('popen_wrappers.py', expect)

    def test_random_module(self):
        '''Test for the `random` module.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 6, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 6}
        }
        self.check_example('random_module.py', expect)

    def test_requests_ssl_verify_disabled(self):
        '''Test for the `requests` library skipping verification.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 7},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 7}
        }
        self.check_example('requests-ssl-verify-disabled.py', expect)

    def test_skip(self):
        '''Test `#nosec` and `#noqa` comments.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 5, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 5}
        }
        self.check_example('skip.py', expect)

    def test_ignore_skip(self):
        '''Test --ignore-nosec flag.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 7, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 7}
        }
        self.check_example('skip.py', expect, ignore_nosec=True)

    def test_sql_statements(self):
        '''Test for SQL injection through string building.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 14, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 8, 'MEDIUM': 6, 'HIGH': 0}
        }
        self.check_example('sql_statements.py', expect)

    def test_ssl_insecure_version(self):
        '''Test for insecure SSL protocol versions.'''
        expect = {
            'SEVERITY': {'LOW': 1, 'MEDIUM': 10, 'HIGH': 7},
            'CONFIDENCE': {'LOW': 0, 'MEDIUM': 11, 'HIGH': 7}
        }
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 1, 'MEDIUM': 10, 'HIGH': 7},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 11, 'HIGH': 7}
        }
        self.check_example('ssl-insecure-version.py', expect)

    def test_subprocess_shell(self):
        '''Test for `subprocess.Popen` with `shell=True`.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 21, 'MEDIUM': 1, 'HIGH': 11},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 1, 'MEDIUM': 0, 'HIGH': 32}
        }
        self.check_example('subprocess_shell.py', expect)

    def test_urlopen(self):
        '''Test for dangerous URL opening.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 14, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 14}
        }
        self.check_example('urlopen.py', expect)

    def test_wildcard_injection(self):
        '''Test for wildcard injection in shell commands.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 10, 'MEDIUM': 0, 'HIGH': 4},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 5, 'HIGH': 9}
        }
        self.check_example('wildcard-injection.py', expect)

    def test_django_sql_injection(self):
        """Test insecure extra functions on Django."""

        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 11, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 11, 'HIGH': 0}
        }
        self.check_example('django_sql_injection_extra.py', expect)

    def test_django_sql_injection_raw(self):
        """Test insecure raw functions on Django."""

        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 4, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 4, 'HIGH': 0}
        }
        self.check_example('django_sql_injection_raw.py', expect)

    def test_yaml(self):
        '''Test for `yaml.load`.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 1, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 1}
        }
        self.check_example('yaml_load.py', expect)

    def test_jinja2_templating(self):
        '''Test jinja templating for potential XSS bugs.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 5},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 2, 'HIGH': 3}
        }
        self.check_example('jinja2_templating.py', expect)

    def test_mako_templating(self):
        '''Test Mako templates for XSS.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 3, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 3}
        }
        self.check_example('mako_templating.py', expect)

    def test_django_xss_secure(self):
        """Test false positives for Django XSS"""
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
        }
        self.b_mgr.b_ts = b_test_set.BanditTestSet(
            config=self.b_mgr.b_conf,
            profile={'exclude': ['B308']}
        )
        self.check_example('mark_safe_secure.py', expect)

    def test_django_xss_insecure(self):
        """Test for Django XSS via django.utils.safestring"""
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 28, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 28}
        }
        self.b_mgr.b_ts = b_test_set.BanditTestSet(
            config=self.b_mgr.b_conf,
            profile={'exclude': ['B308']}
        )
        self.check_example('mark_safe_insecure.py', expect)

    def test_xml(self):
        '''Test xml vulnerabilities.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 1, 'MEDIUM': 4, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 5}
        }
        self.check_example('xml_etree_celementtree.py', expect)

        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 3}
        }
        self.check_example('xml_expatbuilder.py', expect)

        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 3, 'MEDIUM': 1, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 4}
        }
        self.check_example('xml_lxml.py', expect)

        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 2, 'MEDIUM': 2, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 4}
        }
        self.check_example('xml_pulldom.py', expect)

        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 1},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 1}
        }
        self.check_example('xml_xmlrpc.py', expect)

        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 1, 'MEDIUM': 4, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 5}
        }
        self.check_example('xml_etree_elementtree.py', expect)

        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 1, 'MEDIUM': 1, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2}
        }
        self.check_example('xml_expatreader.py', expect)

        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 2, 'MEDIUM': 2, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 4}
        }
        self.check_example('xml_minidom.py', expect)

        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 2, 'MEDIUM': 6, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 8}
        }
        self.check_example('xml_sax.py', expect)

    def test_httpoxy(self):
        '''Test httpoxy vulnerability.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 1},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 1}
        }
        self.check_example('httpoxy_cgihandler.py', expect)
        self.check_example('httpoxy_twisted_script.py', expect)
        self.check_example('httpoxy_twisted_directory.py', expect)

    def test_asserts(self):
        '''Test catching the use of assert.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 1, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 1}
        }
        self.check_example('assert.py', expect)

    def test_paramiko_injection(self):
        '''Test paramiko command execution.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 2, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 2, 'HIGH': 0}
        }
        self.check_example('paramiko_injection.py', expect)

    def test_partial_path(self):
        '''Test process spawning with partial file paths.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 11, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 11}
        }
        self.check_example('partial_path_process.py', expect)

    def test_try_except_continue(self):
        '''Test try, except, continue detection.'''
        test = next((x for x in self.b_mgr.b_ts.tests['ExceptHandler']
                    if x.__name__ == 'try_except_continue'))

        test._config = {'check_typed_exception': True}
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 3, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 3}
        }
        self.check_example('try_except_continue.py', expect)

        test._config = {'check_typed_exception': False}
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 2, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2}
        }
        self.check_example('try_except_continue.py', expect)

    def test_try_except_pass(self):
        '''Test try, except pass detection.'''
        test = next((x for x in self.b_mgr.b_ts.tests['ExceptHandler']
                     if x.__name__ == 'try_except_pass'))

        test._config = {'check_typed_exception': True}
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 3, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 3}
        }
        self.check_example('try_except_pass.py', expect)

        test._config = {'check_typed_exception': False}
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 2, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2}
        }
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
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 8, 'HIGH': 10},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 18}
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
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 1},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 1, 'HIGH': 0}
        }
        self.check_example('flask_debug.py', expect)

    def test_nosec(self):
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
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
        self.assertEqual(1, len(self.b_mgr.baseline))
        self.assertEqual({}, self.b_mgr.get_issue_list())

    def test_blacklist_input(self):
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 1},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 1}
        }
        self.check_example('input.py', expect)

    def test_unverified_context(self):
        '''Test for `ssl._create_unverified_context`.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 1, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 1}
        }
        self.check_example('unverified_context.py', expect)

    def test_hashlib_new_insecure_functions(self):
        '''Test insecure hash functions created by `hashlib.new`.'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 5, 'HIGH': 0},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 5}
        }
        self.check_example('hashlib_new_insecure_functions.py', expect)

    def test_blacklist_pycrypto(self):
        '''Test importing pycrypto module'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2}
        }
        self.check_example('pycrypto.py', expect)

    def test_blacklist_pycryptodome(self):
        '''Test importing pycryptodome module'''
        expect = {
            'SEVERITY': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2},
            'CONFIDENCE': {'UNDEFINED': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 2}
        }
        self.check_example('pycryptodome.py', expect)
