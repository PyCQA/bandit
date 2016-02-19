# Copyright 2016 IBM Corp.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import os
import shutil
import subprocess

import fixtures
import testtools


class BaselineFunctionalTests(testtools.TestCase):

    '''Functional tests for Bandit baseline.

    This set of tests is used to verify that the baseline comparison handles
    finding and comparing results appropriately. The only comparison is the
    number of candidates per file, meaning that any candidates found may
    already exist in the baseline. In this case, all candidates are flagged
    and a user will need to investigate the candidates related to that file.
    '''

    def setUp(self):
        super(BaselineFunctionalTests, self).setUp()
        self.examples_path = 'examples'
        config_path = os.path.join('bandit', 'config', 'bandit.yaml')
        self.baseline_commands = ['bandit', '-r', '-c', config_path]
        self.baseline_report_file = "baseline_report.json"

    def _run_bandit_baseline(self, target_directory, baseline_file):
        '''A helper method to run bandit baseline

        This method will run the bandit baseline test provided an existing
        baseline report and the target directory containing the content to be
        tested.
        :param target_directory: Directory containing content to be compared
        :param baseline_file: File containing an existing baseline report
        :return The baseline test results and return code
        '''
        cmds = self.baseline_commands + ['-b', baseline_file, target_directory]
        process = subprocess.Popen(cmds, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, close_fds=True)
        stdout, stderr = process.communicate()
        return (stdout.decode('utf-8'), process.poll())

    def _create_baseline(self, baseline_paired_files):
        '''A helper method to create a baseline to use during baseline test

        This method will run bandit to create an initial baseline that can
        then be used during the bandit baseline test. Since the file contents
        of the baseline report can be extremely dynamic and difficult to create
        ahead of time, we do this at runtime to reduce the risk of missing
        something. To do this, we must temporary replace the file contents
        with different code which will produce the proper baseline results to
        be used during the baseline test.
        :param baseline_paired_files A dictionary based set of files for which
        to create the baseline report with. For each key file, a value file
        is provided, which contains content to use in place of the key file
        when the baseline report is created initially.
        :return The target directory for the baseline test and the return code
        of the bandit run to help determine whether the baseline report was
        populated
        '''
        target_directory = self.useFixture(fixtures.TempDir()).path
        baseline_results = os.path.join(target_directory,
                                        self.baseline_report_file)
        for key_file, value_file in baseline_paired_files.items():
            shutil.copy(os.path.join(self.examples_path, value_file),
                        os.path.join(target_directory, key_file))
        cmds = self.baseline_commands + ['-f', 'json', '-o', baseline_results,
                                         target_directory]
        process = subprocess.Popen(cmds, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, close_fds=True)
        stdout, stderr = process.communicate()
        return_code = process.poll()
        for key_file, value_file in baseline_paired_files.items():
            shutil.copy(os.path.join(self.examples_path, key_file),
                        os.path.join(target_directory, key_file))
        return (target_directory, return_code)

    def test_no_new_candidates(self):
        '''Tests when there are no new candidates

        Test that bandit returns no issues found, as there are no new
        candidates found compared with those found from the baseline.
        '''
        baseline_report_files = {"new_candidates-all.py":
                                 "new_candidates-all.py"}
        target_directory, baseline_code = (self._create_baseline(
                                           baseline_report_files))
        # assert the initial baseline found results
        self.assertEqual(1, baseline_code)
        baseline_report = os.path.join(target_directory,
                                       self.baseline_report_file)
        return_value, return_code = (self._run_bandit_baseline(
                                     target_directory, baseline_report))
        # assert there were no results (no candidates found)
        self.assertEqual(0, return_code)
        self.assertIn("Total lines of code: 12", return_value)
        self.assertIn("Total lines skipped (#nosec): 3", return_value)
        self.assertIn("Files skipped (0):", return_value)
        self.assertIn("No issues identified.", return_value)

    def test_no_existing_no_new_candidates(self):
        '''Tests when there are no new or existing candidates

        Test file with no existing candidates from baseline and no new
        candidates.
        '''
        baseline_report_files = {"okay.py": "okay.py"}
        target_directory, baseline_code = (self._create_baseline(
                                           baseline_report_files))
        # assert the initial baseline found nothing
        self.assertEqual(0, baseline_code)
        baseline_report = os.path.join(target_directory,
                                       self.baseline_report_file)
        return_value, return_code = (self._run_bandit_baseline(
                                     target_directory, baseline_report))
        # assert there were no results (no candidates found)
        self.assertEqual(0, return_code)
        self.assertIn("Total lines of code: 1", return_value)
        self.assertIn("Total lines skipped (#nosec): 0", return_value)
        self.assertIn("Files skipped (0):", return_value)
        self.assertIn("No issues identified.", return_value)
