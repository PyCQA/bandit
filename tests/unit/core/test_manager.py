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

import os
import sys

import fixtures
import mock
import testtools

from bandit.core import config
from bandit.core import constants
from bandit.core import issue
from bandit.core import manager


class ManagerTests(testtools.TestCase):

    def _get_issue_instance(self, sev=constants.MEDIUM, conf=constants.MEDIUM):
        new_issue = issue.Issue(sev, conf, 'Test issue')
        new_issue.fname = 'code.py'
        new_issue.test = 'bandit_plugin'
        new_issue.lineno = 1
        return new_issue

    def setUp(self):
        super(ManagerTests, self).setUp()
        self.profile = {}
        self.profile['include'] = {
            'any_other_function_with_shell_equals_true',
            'assert_used'}

        self.config = config.BanditConfig()
        self.manager = manager.BanditManager(config=self.config,
                                             agg_type='file',
                                             debug=False,
                                             verbose=False)

    def test_create_manager(self):
        # make sure we can create a manager
        self.assertEqual(self.manager.debug, False)
        self.assertEqual(self.manager.verbose, False)
        self.assertEqual(self.manager.agg_type, 'file')

    def test_create_manager_with_profile(self):
        # make sure we can create a manager
        m = manager.BanditManager(config=self.config, agg_type='file',
                                  debug=False, verbose=False,
                                  profile=self.profile)

        self.assertEqual(m.debug, False)
        self.assertEqual(m.verbose, False)
        self.assertEqual(m.agg_type, 'file')

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

    def test_populate_baseline_success(self):
        # Test populate_baseline with valid JSON
        baseline_data = """{
            "results": [
                {
                    "code": "test code",
                    "filename": "example_file.py",
                    "issue_severity": "low",
                    "issue_confidence": "low",
                    "issue_text": "test issue",
                    "test_name": "some_test",
                    "test_id": "x",
                    "line_number": "n",
                    "line_range": "n-m"
                }
            ]
        }
        """
        issue_dictionary = {"code": "test code", "filename": "example_file.py",
                            "issue_severity": "low", "issue_confidence": "low",
                            "issue_text": "test issue", "test_name":
                            "some_test", "test_id": "x", "line_number": "n",
                            "line_range": "n-m"}
        baseline_items = [issue.issue_from_dict(issue_dictionary)]
        self.manager.populate_baseline(baseline_data)
        self.assertEqual(baseline_items, self.manager.baseline)

    @mock.patch('logging.Logger.warning')
    def test_populate_baseline_invalid_json(self, mock_logger_warning):
        # Test populate_baseline with invalid JSON content
        baseline_data = """{"data": "bad"}"""
        self.manager.populate_baseline(baseline_data)
        # Default value for manager.baseline is []
        self.assertEqual([], self.manager.baseline)
        self.assertTrue(mock_logger_warning.called)

    def test_results_count(self):
        levels = [constants.LOW, constants.MEDIUM, constants.HIGH]
        self.manager.results = (
            [issue.Issue(severity=l, confidence=l) for l in levels])

        r = [self.manager.results_count(sev_filter=l, conf_filter=l)
             for l in levels]

        self.assertEqual([3, 2, 1], r)

    def test_output_results_invalid_format(self):
        # Test that output_results succeeds given an invalid format
        temp_directory = self.useFixture(fixtures.TempDir()).path
        lines = 5
        sev_level = constants.LOW
        conf_level = constants.LOW
        output_filename = os.path.join(temp_directory, "_temp_output")
        output_format = "invalid"
        tmp_file = open(output_filename, 'w')
        self.manager.output_results(lines, sev_level, conf_level, tmp_file,
                                    output_format)
        if sys.stdout.isatty():
            self.assertFalse(os.path.isfile(output_filename))
        else:
            self.assertTrue(os.path.isfile(output_filename))

    def test_output_results_valid_format(self):
        # Test that output_results succeeds given a valid format
        temp_directory = self.useFixture(fixtures.TempDir()).path
        lines = 5
        sev_level = constants.LOW
        conf_level = constants.LOW
        output_filename = os.path.join(temp_directory, "_temp_output.txt")
        output_format = "txt"
        tmp_file = open(output_filename, 'w')
        self.manager.output_results(lines, sev_level, conf_level, tmp_file,
                                    output_format)
        self.assertTrue(os.path.isfile(output_filename))

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
            m.assert_called_with('c', ['*.py', '*.pyw'], ['a', 'b'],
                                 enforce_glob=False)

    @mock.patch('os.path.isdir')
    def test_discover_files_include(self, isdir):
        isdir.return_value = False
        with mock.patch.object(manager, '_is_file_included') as m:
            m.return_value = True
            self.manager.discover_files(['thing'], True)
            self.assertEqual(self.manager.files_list, ['thing'])
            self.assertEqual(self.manager.excluded_files, [])

    def test_run_tests_keyboardinterrupt(self):
        # Test that bandit manager exits when there is a keyboard interrupt
        temp_directory = self.useFixture(fixtures.TempDir()).path
        some_file = os.path.join(temp_directory, 'some_code_file.py')
        with open(some_file, 'wt') as fd:
            fd.write('some_code = x + 1')
        self.manager.files_list = [some_file]
        with mock.patch('bandit.core.metrics.Metrics.count_issues'
                        ) as mock_count_issues:
            mock_count_issues.side_effect = KeyboardInterrupt
            # assert a SystemExit with code 2
            self.assertRaisesRegex(SystemExit, '2', self.manager.run_tests)

    def test_run_tests_ioerror(self):
        # Test that a file name is skipped and added to the manager.skipped
        # list when there is an IOError attempting to open/read the file
        temp_directory = self.useFixture(fixtures.TempDir()).path
        no_such_file = os.path.join(temp_directory, 'no_such_file.py')
        self.manager.files_list = [no_such_file]
        self.manager.run_tests()
        # since the file name and the IOError.strerror text are added to
        # manager.skipped, we convert skipped to str to find just the file name
        # since IOError is not constant
        self.assertIn(no_such_file, str(self.manager.skipped))

    def test_compare_baseline(self):
        issue_a = self._get_issue_instance()
        issue_a.fname = 'file1.py'

        issue_b = self._get_issue_instance()
        issue_b.fname = 'file2.py'

        issue_c = self._get_issue_instance(sev=constants.HIGH)
        issue_c.fname = 'file1.py'

        # issue c is in results, not in baseline
        self.assertEqual(
            [issue_c],
            manager._compare_baseline_results([issue_a, issue_b],
                                              [issue_a, issue_b, issue_c]))

        # baseline and results are the same
        self.assertEqual(
            [],
            manager._compare_baseline_results([issue_a, issue_b, issue_c],
                                              [issue_a, issue_b, issue_c]))

        # results are better than baseline
        self.assertEqual(
            [],
            manager._compare_baseline_results([issue_a, issue_b, issue_c],
                                              [issue_a, issue_b]))

    def test_find_candidate_matches(self):
        issue_a = self._get_issue_instance()
        issue_b = self._get_issue_instance()

        issue_c = self._get_issue_instance()
        issue_c.fname = 'file1.py'

        # issue a and b are the same, both should be returned as candidates
        self.assertEqual({issue_a: [issue_a, issue_b]},
                         manager._find_candidate_matches([issue_a],
                                                         [issue_a, issue_b]))

        # issue a and c are different, only a should be returned
        self.assertEqual({issue_a: [issue_a]},
                         manager._find_candidate_matches([issue_a],
                                                         [issue_a, issue_c]))

        # c doesn't match a, empty list should be returned
        self.assertEqual({issue_a: []},
                         manager._find_candidate_matches([issue_a], [issue_c]))

        # a and b match, a and b should both return a and b candidates
        self.assertEqual(
            {issue_a: [issue_a, issue_b], issue_b: [issue_a, issue_b]},
            manager._find_candidate_matches([issue_a, issue_b],
                                            [issue_a, issue_b, issue_c]))
