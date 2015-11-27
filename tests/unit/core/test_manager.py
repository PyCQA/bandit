# -*- coding:utf-8 -*-
#
# Copyright 2015 Hewlett-Packard Development Company, L.P.
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

import fixtures
import mock
import six
import os
import tempfile
import testtools

from bandit.core import manager
from bandit.core import config
from bandit.core import issue
from bandit.core import constants
from bandit.core import extension_loader


class TempFile(fixtures.Fixture):
    def __init__(self, contents=None):
        super(TempFile, self).__init__()
        self.contents = contents

    def setUp(self):
        super(TempFile, self).setUp()

        with tempfile.NamedTemporaryFile(mode='wt', delete=False) as f:
            if self.contents:
                f.write(self.contents)

        self.addCleanup(os.unlink, f.name)

        self.name = f.name


class ManagerTests(testtools.TestCase):

    def _get_issue_instance(self, sev=constants.MEDIUM, conf=constants.MEDIUM):
        new_issue = issue.Issue(sev, conf, 'Test issue')
        new_issue.fname = 'code.py'
        new_issue.test = 'bandit_plugin'
        new_issue.lineno = 1
        return new_issue

    def setUp(self):
        super(ManagerTests, self).setUp()
        contents = """
            profiles:
                Test:
                    include:
                        - any_other_function_with_shell_equals_true
                        - assert_used
        """
        f = self.useFixture(TempFile(contents))
        self.config = config.BanditConfig(f.name)
        self.manager = manager.BanditManager(config=self.config,
                                             agg_type='file',
                                             debug=False,
                                             verbose=False,
                                             profile_name=None)

    def test_create_manager(self):
        # make sure we can create a manager
        self.assertEqual(self.manager.debug, False)
        self.assertEqual(self.manager.verbose, False)
        self.assertEqual(self.manager.agg_type, 'file')
        self.assertTrue(self.manager.has_tests)

    def test_create_manager_with_profile(self):
        # make sure we can create a manager
        m = manager.BanditManager(config=self.config, agg_type='file',
                                  debug=False, verbose=False,
                                  profile_name='Test')

        self.assertEqual(m.debug, False)
        self.assertEqual(m.verbose, False)
        self.assertEqual(m.agg_type, 'file')
        self.assertTrue(self.manager.has_tests)


    def test_create_manager_with_profile_bad(self):
        try:
            m = manager.BanditManager(config=self.config, agg_type='file',
                                      debug=False, verbose=False,
                                      profile_name='Bad')
        except RuntimeError as e:
            err = str(e)

        self.assertTrue(err.startswith(
            "unable to find profile (Bad) in config file:"))

    def test_matches_globlist(self):
        self.assertTrue(manager._matches_glob_list('test', ['*tes*']))
        self.assertFalse(manager._matches_glob_list('test', ['*fes*']))

    def test_is_file_included(self):
        a = manager._is_file_included(path='a.py', included_globs=['*.py'],
                                      excluded_path_strings='',
                                      enforce_glob=True)

        b = manager._is_file_included(path='a.dd', included_globs=['*.py'],
                                      excluded_path_strings='',
                                      enforce_glob=False)

        c = manager._is_file_included(path='a.py', included_globs=['*.py'],
                                      excluded_path_strings='a.py',
                                      enforce_glob=True)

        d = manager._is_file_included(path='a.dd', included_globs=['*.py'],
                                      excluded_path_strings='',
                                      enforce_glob=True)
        self.assertTrue(a)
        self.assertTrue(b)
        self.assertFalse(c)
        self.assertFalse(d)


    @mock.patch('os.walk')
    def test_get_files_from_dir(self, os_walk):
        os_walk.return_value = [
            ('/', ('a'), ()),
            ('/a', (), ('a.py', 'b.py', 'c.ww'))
        ]

        inc, exc = manager._get_files_from_dir(files_dir='',
                                               included_globs=['*.py'],
                                               excluded_path_strings=None)

        self.assertEqual(exc, set(['/a/c.ww']))
        self.assertEqual(inc, set(['/a/a.py', '/a/b.py']))

    def test_results_count(self):
        levels = [constants.LOW, constants.MEDIUM, constants.HIGH]
        self.manager.results = (
            [issue.Issue(severity=l, confidence=l) for l in levels])

        r = [self.manager.results_count(sev_filter=l, conf_filter=l) \
                for l in levels]

        self.assertEqual([3,2,1], r)

    @mock.patch('os.path.isdir')
    def test_discover_files_recurse_skip(self, isdir):
        isdir.return_value = True
        self.manager.discover_files(['thing'], False)
        self.assertEqual(self.manager.files_list, [])
        self.assertEqual(self.manager.excluded_files, [])

    @mock.patch('os.path.isdir')
    def test_discover_files_recurse_files(self, isdir):
        isdir.return_value = True
        with mock.patch.object(manager, '_get_files_from_dir') as m:
            m.return_value = (set(['files']), set(['excluded']))
            self.manager.discover_files(['thing'], True)
            self.assertEqual(self.manager.files_list, ['files'])
            self.assertEqual(self.manager.excluded_files, ['excluded'])

    @mock.patch('os.path.isdir')
    def test_discover_files_exclude(self, isdir):
        isdir.return_value = False
        with mock.patch.object(manager, '_is_file_included') as m:
            m.return_value = False
            self.manager.discover_files(['thing'], True)
            self.assertEqual(self.manager.files_list, [])
            self.assertEqual(self.manager.excluded_files, ['thing'])

    @mock.patch('os.path.isdir')
    def test_discover_files_exclude_cmdline(self, isdir):
        isdir.return_value = False
        with mock.patch.object(manager, '_is_file_included') as m:
            self.manager.discover_files(['a', 'b', 'c'], True,
                                        excluded_paths='a,b')
            m.assert_called_with('c', ['*.py'], ['a', 'b'], enforce_glob=False)

    @mock.patch('os.path.isdir')
    def test_discover_files_include(self, isdir):
        isdir.return_value = False
        with mock.patch.object(manager, '_is_file_included') as m:
            m.return_value = True
            self.manager.discover_files(['thing'], True)
            self.assertEqual(self.manager.files_list, ['thing'])
            self.assertEqual(self.manager.excluded_files, [])

    def test_compare_baseline(self):
        issue_a = self._get_issue_instance()
        issue_a.fname = 'file1.py'

        issue_b = self._get_issue_instance()
        issue_b.fname = 'file2.py'

        issue_c = self._get_issue_instance(sev=constants.HIGH)
        issue_c.fname = 'file1.py'

        # issue c is in results, not in baseline
        self.assertEqual([issue_c],
                         manager._compare_baseline_results(
                             [issue_a, issue_b],
                             [issue_a, issue_b, issue_c]))

        # baseline and results are the same
        self.assertEqual([],
                         manager._compare_baseline_results([issue_a, issue_b, issue_c],
                                                           [issue_a, issue_b, issue_c]))

        # results are better than baseline
        self.assertEqual([],
                         manager._compare_baseline_results([issue_a, issue_b, issue_c],
                                                           [issue_a, issue_b]))

    def test_find_candidate_matches(self):
        issue_a = self._get_issue_instance()
        issue_b = self._get_issue_instance()

        issue_c = self._get_issue_instance()
        issue_c.fname = 'file1.py'

        # issue a and b are the same, both should be returned as candidates
        self.assertEqual({issue_a: [issue_a, issue_b]},
                         manager._find_candidate_matches([issue_a], [issue_a, issue_b]))

        # issue a and c are different, only a should be returned
        self.assertEqual({issue_a: [issue_a]},
                         manager._find_candidate_matches([issue_a], [issue_a, issue_c]))

        # c doesn't match a, empty list should be returned
        self.assertEqual({issue_a: []},
                         manager._find_candidate_matches([issue_a], [issue_c]))

        # a and b match, a and b should both return a and b candidates
        self.assertEqual({issue_a: [issue_a, issue_b],
                          issue_b: [issue_a, issue_b]},

                         manager._find_candidate_matches([issue_a, issue_b],
                                                         [issue_a, issue_b, issue_c]))
