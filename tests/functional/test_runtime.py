# Copyright (c) 2015 VMware, Inc.
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
import subprocess

import six
import testtools


class RuntimeTests(testtools.TestCase):

    def _test_runtime(self, cmdlist):
        process = subprocess.Popen(
            cmdlist,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True
        )
        stdout, stderr = process.communicate()
        retcode = process.poll()
        return (retcode, stdout.decode('utf-8'))

    def _test_example(self, cmdlist, targets):
        for t in targets:
            cmdlist.append(os.path.join(os.getcwd(), 'examples', t))
        return self._test_runtime(cmdlist)

    # test direct execution of bandit
    def test_no_arguments(self):
        (retcode, output) = self._test_runtime(['bandit', ])
        self.assertEqual(2, retcode)
        if six.PY2:
            self.assertIn("error: too few arguments", output)
        else:
            self.assertIn("arguments are required: targets", output)

    def test_nonexistent_config(self):
        (retcode, output) = self._test_runtime([
            'bandit', '-c', 'nonexistent.yml', 'xx.py'
        ])
        self.assertEqual(2, retcode)
        self.assertIn("nonexistent.yml : Could not read config file.", output)

    def test_help_arg(self):
        (retcode, output) = self._test_runtime(['bandit', '-h'])
        self.assertEqual(0, retcode)
        self.assertIn("Bandit - a Python source code analyzer.", output)
        self.assertIn("usage: bandit [-h]", output)
        self.assertIn("positional arguments:", output)
        self.assertIn("optional arguments:", output)
        self.assertIn("plugin suites were discovered and loaded:", output)

    def test_help_in_readme(self):
        replace_list = [' ', '\t']
        (retcode, output) = self._test_runtime(['bandit', '-h'])
        for i in replace_list:
            output = output.replace(i, '')
        output = output.replace("'", "\'")
        with open('README.rst') as f:
            readme = f.read()
            for i in replace_list:
                readme = readme.replace(i, '')
            self.assertIn(output, readme)

    # test examples (use _test_example() to wrap in config location argument
    def test_example_nonexistent(self):
        (retcode, output) = self._test_example(
            ['bandit', ], ['nonexistent.py', ]
        )
        self.assertEqual(0, retcode)
        self.assertIn("Files skipped (1):", output)
        self.assertIn("nonexistent.py (No such file or directory", output)

    def test_example_okay(self):
        (retcode, output) = self._test_example(['bandit', ], ['okay.py', ])
        self.assertEqual(0, retcode)
        self.assertIn("Total lines of code: 1", output)
        self.assertIn("Files skipped (0):", output)
        self.assertIn("No issues identified.", output)

    def test_example_nonsense(self):
        (retcode, output) = self._test_example(['bandit', ], ['nonsense.py', ])
        self.assertEqual(0, retcode)
        self.assertIn("Files skipped (1):", output)
        self.assertIn("nonsense.py (syntax error while parsing AST", output)

    def test_example_imports(self):
        (retcode, output) = self._test_example(['bandit', ], ['imports.py', ])
        self.assertEqual(1, retcode)
        self.assertIn("Total lines of code: 4", output)
        self.assertIn("Low: 2", output)
        self.assertIn("High: 2", output)
        self.assertIn("Files skipped (0):", output)
        self.assertIn("Issue: [B403:blacklist] Consider possible",
                      output)
        self.assertIn("imports.py:2", output)
        self.assertIn("imports.py:4", output)
