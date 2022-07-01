# SPDX-License-Identifier: Apache-2.0
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class InjectionWildcardTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B609"])

    def test_os_system_tar(self):
        fdata = textwrap.dedent(
            """
            import os
            os.system("/bin/tar xvzf *")
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.IMPROPER_WILDCARD_NEUTRALIZATION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_system_chown(self):
        fdata = textwrap.dedent(
            """
            import os
            os.system('/bin/chown *')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.IMPROPER_WILDCARD_NEUTRALIZATION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_system_chmod(self):
        fdata = textwrap.dedent(
            """
            import os
            os.popen2('/bin/chmod *')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.IMPROPER_WILDCARD_NEUTRALIZATION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_popen_chown_shell_true(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.Popen('/bin/chown *', shell=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(
            b_issue.Cwe.IMPROPER_WILDCARD_NEUTRALIZATION, issue.cwe.id
        )
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_popen_rsync(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.Popen('/bin/rsync *')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_subprocess_popen_chmod(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.Popen("/bin/chmod *")
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_subprocess_popen_chown(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.Popen(['/bin/chown', '*'])
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_subprocess_popen_chmod_argv(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.Popen(["/bin/chmod", sys.argv[1], "*"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_os_spawnvp(self):
        fdata = textwrap.dedent(
            """
            import os
            os.spawnvp(os.P_WAIT, 'tar', ['tar', 'xvzf', '*'])
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))
