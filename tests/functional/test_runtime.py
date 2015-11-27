import os
import six
import subprocess
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
        cmdlist.extend([
            '-c',
            os.path.join(os.getcwd(), 'bandit', 'config', 'bandit.yaml')
        ])
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
        self.assertIn("Could not open config file: nonexistent.yml", output)

    def test_help_arg(self):
        (retcode, output) = self._test_runtime(['bandit', '-h'])
        self.assertEqual(0, retcode)
        self.assertIn("Bandit - a Python source code analyzer.", output)
        self.assertIn("usage: bandit [-h]", output)
        self.assertIn("positional arguments:", output)
        self.assertIn("optional arguments:", output)
        self.assertIn("plugin suites were discovered and loaded:", output)

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
        self.assertIn("Issue: [blacklist_imports] Consider possible", output)
        self.assertIn("imports.py:2", output)
        self.assertIn("imports.py:4", output)
