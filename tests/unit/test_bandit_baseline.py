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

import bandit.cli.baseline as baseline

import fixtures
import os
import subprocess
import testtools

import git

config = """
include:
    - '*.py'
    - '*.pyw'

profiles:
    test:
        include:
            - start_process_with_a_shell

shell_injection:
    subprocess:

    shell:
        - os.system
"""

class BanditBaselineToolTests(testtools.TestCase):

    def test_bandit_baseline(self):
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

        baseline_command = ['bandit-baseline', '-r', '.', '-p', 'test']

        for branch in branches:
            branch['branch'] = git_repo.create_head(branch['name'])
            git_repo.head.reference = branch['branch']
            git_repo.head.reset(working_tree=True)

            for f in branch['files']:
                with open(f, 'wt') as fd:
                    fd.write(contents[f])

            git_repo.index.add(branch['files'])
            git_repo.index.commit(branch['name'])

            self.assertEqual(subprocess.call(baseline_command),
                             branch['expected_return'])

    def test_main_non_repo(self):
        repo_dir = self.useFixture(fixtures.TempDir()).path
        os.chdir(repo_dir)

        # assert the system exits with code 2
        self.assertRaisesRegex(SystemExit, '2', baseline.main)

    def test_main_no_commit(self):
        repo_directory = self.useFixture(fixtures.TempDir()).path

        git_repo = git.Repo.init(repo_directory)
        git_repo.index.commit('Initial Commit')
        os.chdir(repo_directory)

        # assert the system exist with code 2
        self.assertRaisesRegex(SystemExit, '2', baseline.main)

    def test_init_logger(self):
        baseline.init_logger()
        logger = baseline.logger

        # verify that logger was initialized
        self.assertIsNotNone(logger)

    def test_initialize_no_repo(self):
        repo_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(repo_directory)
        return_value = baseline.initialize()
        self.assertEquals(return_value, (None, None, None))
