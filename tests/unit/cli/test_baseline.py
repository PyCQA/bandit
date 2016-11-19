# -*- coding:utf-8 -*-
#
# Copyright 2015 Hewlett-Packard Enterprise
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
import subprocess

import fixtures
import git
import mock
import testtools

import bandit.cli.baseline as baseline


config = """
include:
    - '*.py'
    - '*.pyw'

profiles:
    test:
        include:
            - start_process_with_a_shell

shell_injection:
    subprocess: []
    no_shell: []
    shell:
        - os.system
"""


class BanditBaselineToolTests(testtools.TestCase):

    @classmethod
    def setUpClass(cls):
        # Set up prior to running test class
        # read in content used for temporary file contents
        with open('examples/mktemp.py') as fd:
            cls.temp_file_contents = fd.read()

    def setUp(self):
        # Set up prior to run each test case
        super(BanditBaselineToolTests, self).setUp()
        self.current_directory = os.getcwd()

    def tearDown(self):
        # Tear down after running each test case
        super(BanditBaselineToolTests, self).tearDown()
        os.chdir(self.current_directory)

    def test_bandit_baseline(self):
        # Tests running bandit via the CLI (baseline) with benign and malicious
        # content
        repo_directory = self.useFixture(fixtures.TempDir()).path

        # get benign and findings examples
        with open('examples/okay.py') as fd:
            benign_contents = fd.read()

        with open('examples/os_system.py') as fd:
            malicious_contents = fd.read()

        contents = {'benign_one.py': benign_contents,
                    'benign_two.py': benign_contents,
                    'malicious.py': malicious_contents}

        # init git repo, change directory to it
        git_repo = git.Repo.init(repo_directory)
        git_repo.index.commit('Initial commit')
        os.chdir(repo_directory)

        with open('bandit.yaml', 'wt') as fd:
            fd.write(config)

        # create three branches, first has only benign, second adds malicious,
        # third adds benign

        branches = [{'name': 'benign1',
                     'files': ['benign_one.py'],
                     'expected_return': 0},

                    {'name': 'malicious',
                     'files': ['benign_one.py', 'malicious.py'],
                     'expected_return': 1},

                    {'name': 'benign2',
                     'files': ['benign_one.py', 'malicious.py',
                               'benign_two.py'],
                     'expected_return': 0}]

        baseline_command = ['bandit-baseline', '-c', 'bandit.yaml', '-r', '.',
                            '-p', 'test']

        for branch in branches:
            branch['branch'] = git_repo.create_head(branch['name'])
            git_repo.head.reference = branch['branch']
            git_repo.head.reset(working_tree=True)

            for f in branch['files']:
                with open(f, 'wt') as fd:
                    fd.write(contents[f])

            git_repo.index.add(branch['files'])
            git_repo.index.commit(branch['name'])

            self.assertEqual(branch['expected_return'],
                             subprocess.call(baseline_command))

    def test_main_non_repo(self):
        # Test that bandit gracefully exits when there is no git repository
        # when calling main
        repo_dir = self.useFixture(fixtures.TempDir()).path
        os.chdir(repo_dir)

        # assert the system exits with code 2
        self.assertRaisesRegex(SystemExit, '2', baseline.main)

    def test_main_git_command_failure(self):
        # Test that bandit does not run when the Git command fails
        repo_directory = self.useFixture(fixtures.TempDir()).path
        git_repo = git.Repo.init(repo_directory)
        git_repo.index.commit('Initial Commit')
        os.chdir(repo_directory)

        additional_content = 'additional_file.py'
        with open(additional_content, 'wt') as fd:
            fd.write(self.temp_file_contents)
        git_repo.index.add([additional_content])
        git_repo.index.commit('Additional Content')

        with mock.patch('git.Repo.commit') as mock_git_repo_commit:
            mock_git_repo_commit.side_effect = git.exc.GitCommandError(
                'commit', '')

            # assert the system exits with code 2
            self.assertRaisesRegex(SystemExit, '2', baseline.main)

    def test_main_no_parent_commit(self):
        # Test that bandit exits when there is no parent commit detected when
        # calling main
        repo_directory = self.useFixture(fixtures.TempDir()).path

        git_repo = git.Repo.init(repo_directory)
        git_repo.index.commit('Initial Commit')
        os.chdir(repo_directory)

        # assert the system exits with code 2
        self.assertRaisesRegex(SystemExit, '2', baseline.main)

    def test_main_subprocess_error(self):
        # Test that bandit handles a CalledProcessError when attempting to run
        # bandit baseline via a subprocess
        repo_directory = self.useFixture(fixtures.TempDir()).path

        git_repo = git.Repo.init(repo_directory)
        git_repo.index.commit('Initial Commit')
        os.chdir(repo_directory)

        additional_content = 'additional_file.py'
        with open(additional_content, 'wt') as fd:
            fd.write(self.temp_file_contents)
        git_repo.index.add([additional_content])
        git_repo.index.commit('Additional Content')

        with mock.patch('subprocess.check_output') as mock_check_output:
            mock_bandit_cmd = 'bandit_mock -b temp_file.txt'
            mock_check_output.side_effect = (
                subprocess.CalledProcessError('3', mock_bandit_cmd)
            )

            # assert the system exits with code 3 (returned from
            # CalledProcessError)
            self.assertRaisesRegex(SystemExit, '3', baseline.main)

    def test_init_logger(self):
        # Test whether the logger was initialized when calling init_logger
        baseline.init_logger()
        logger = baseline.LOG

        # verify that logger was initialized
        self.assertIsNotNone(logger)

    def test_initialize_no_repo(self):
        # Test that bandit does not run when there is no current git
        # repository when calling initialize
        repo_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(repo_directory)

        return_value = baseline.initialize()

        # assert bandit did not run due to no git repo
        self.assertEqual((None, None, None), return_value)

    def test_initialize_git_command_failure(self):
        # Test that bandit does not run when the Git command fails
        repo_directory = self.useFixture(fixtures.TempDir()).path
        git_repo = git.Repo.init(repo_directory)
        git_repo.index.commit('Initial Commit')
        os.chdir(repo_directory)

        additional_content = 'additional_file.py'
        with open(additional_content, 'wt') as fd:
            fd.write(self.temp_file_contents)
        git_repo.index.add([additional_content])
        git_repo.index.commit('Additional Content')

        with mock.patch('git.Repo') as mock_git_repo:
            mock_git_repo.side_effect = git.exc.GitCommandNotFound('clone', '')

            return_value = baseline.initialize()

            # assert bandit did not run due to git command failure
            self.assertEqual((None, None, None), return_value)

    def test_initialize_dirty_repo(self):
        # Test that bandit does not run when the current git repository is
        # 'dirty' when calling the initialize method
        repo_directory = self.useFixture(fixtures.TempDir()).path
        git_repo = git.Repo.init(repo_directory)
        git_repo.index.commit('Initial Commit')
        os.chdir(repo_directory)

        # make the git repo 'dirty'
        with open('dirty_file.py', 'wt') as fd:
            fd.write(self.temp_file_contents)
        git_repo.index.add(['dirty_file.py'])

        return_value = baseline.initialize()

        # assert bandit did not run due to dirty repo
        self.assertEqual((None, None, None), return_value)

    @mock.patch('sys.argv', ['bandit', '-f', 'txt', 'test'])
    def test_initialize_existing_report_file(self):
        # Test that bandit does not run when the output file exists (and the
        # provided output format does not match the default format) when
        # calling the initialize method
        repo_directory = self.useFixture(fixtures.TempDir()).path
        git_repo = git.Repo.init(repo_directory)
        git_repo.index.commit('Initial Commit')
        os.chdir(repo_directory)

        # create an existing version of output report file
        existing_report = "{}.{}".format(baseline.report_basename, 'txt')
        with open(existing_report, 'wt') as fd:
            fd.write(self.temp_file_contents)

        return_value = baseline.initialize()

        # assert bandit did not run due to existing report file
        self.assertEqual((None, None, None), return_value)

    @mock.patch('bandit.cli.baseline.bandit_args', ['-o',
                'bandit_baseline_result'])
    def test_initialize_with_output_argument(self):
        # Test that bandit does not run when the '-o' (output) argument is
        # specified
        repo_directory = self.useFixture(fixtures.TempDir()).path
        git_repo = git.Repo.init(repo_directory)
        git_repo.index.commit('Initial Commit')
        os.chdir(repo_directory)

        return_value = baseline.initialize()

        # assert bandit did not run due to provided -o (--ouput) argument
        self.assertEqual((None, None, None), return_value)

    def test_initialize_existing_temp_file(self):
        # Test that bandit does not run when the temporary output file exists
        # when calling the initialize method
        repo_directory = self.useFixture(fixtures.TempDir()).path
        git_repo = git.Repo.init(repo_directory)
        git_repo.index.commit('Initial Commit')
        os.chdir(repo_directory)

        # create an existing version of temporary output file
        existing_temp_file = baseline.baseline_tmp_file
        with open(existing_temp_file, 'wt') as fd:
            fd.write(self.temp_file_contents)

        return_value = baseline.initialize()

        # assert bandit did not run due to existing temporary report file
        self.assertEqual((None, None, None), return_value)
