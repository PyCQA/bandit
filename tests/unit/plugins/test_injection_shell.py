# SPDX-License-Identifier: Apache-2.0
import sys
import textwrap

import bandit
from bandit.core import issue as b_issue
from tests.unit.plugins import base_test_case


class InjectionShellTests(base_test_case.BaseTestCase):
    def setUp(self):
        super().setUp(["B602", "B603", "B604", "B605", "B606", "B607"])

    def test_popen_shell_true(self):
        fdata = textwrap.dedent(
            """
            from subprocess import Popen
            Popen('/bin/gcc --version', shell=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_popen_shell_true(self):
        fdata = textwrap.dedent(
            """
            def Popen(*args, **kwargs):
                print('hi')

                def __len__(self):
                    return 0
            Popen('/bin/gcc --version', shell=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B604", issue.test_id)
        self.assertEqual(bandit.MEDIUM, issue.severity)
        self.assertEqual(bandit.LOW, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(7, issue.lineno)
        self.assertEqual([7], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_popen_arg_list_shell_false(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.Popen(['/bin/gcc', '--version'], shell=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_popen_arg_list(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.Popen(['/bin/gcc', '--version'])
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_arg_list_multiline(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.call(["/bin/ls",
                             "-l"
                             ])
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        if sys.version_info >= (3, 8):
            self.assertEqual([3, 4, 5], issue.linerange)
        else:
            self.assertEqual([3, 4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_shell_true(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.call('/bin/ls -l', shell=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_check_call_arg_list_shell_false(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.check_call(['/bin/ls', '-l'], shell=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_check_call_shell_true(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.check_call('/bin/ls -l', shell=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_check_output_arg_list(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.check_output(['/bin/ls', '-l'])
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_check_output_shell_true(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.check_output('/bin/ls -l', shell=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_run_shell_arg_list(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.run(['/bin/ls', '-l'])
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_run_shell_shell_true(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.run('/bin/ls -l', shell=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_popen_wildcard_shell_true(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.Popen('/bin/ls *', shell=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_popen_string_sub_shell_true(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.Popen('/bin/ls %s' % ('something',), shell=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_popen_string_format_shell_true(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.Popen('/bin/ls {}'.format('something'), shell=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_popen_command_as_var_shell_true(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = "/bin/ls" + unknown_function()
            subprocess.Popen(command, shell=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_popen_and_shell_true(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            subprocess.Popen('/bin/ls && cat /etc/passwd', shell=True)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_command_as_var_shell_true(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = 'pwd'
            subprocess.call(command, shell='True')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_command_as_var_shell_false_str(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = 'pwd'
            subprocess.call(command, shell='False')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_command_as_var_shell_none_str(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = 'pwd'
            subprocess.call(command, shell='None')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_command_as_var_shell_1(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = 'pwd'
            subprocess.call(command, shell=1)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_command_as_var_shell_popen(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = 'pwd'
            subprocess.call(command, shell=Popen())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_command_as_var_shell_true_list(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = 'pwd'
            subprocess.call(command, shell=[True])
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_command_as_var_shell_dict(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = 'pwd'
            subprocess.call(command, shell={'IS': 'True'})
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_command_as_var_shell_var(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = 'pwd'
            subprocess.call(command, shell=command)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B602", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_command_as_var_shell_false(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = 'pwd'
            subprocess.call(command, shell=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_command_as_var_shell_0(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = 'pwd'
            subprocess.call(command, shell=0)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_command_as_var_shell_empty_list(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = 'pwd'
            subprocess.call(command, shell=[])
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_command_as_var_shell_empty_dict(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = 'pwd'
            subprocess.call(command, shell={})
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_subprocess_call_command_as_var_shell_none(self):
        fdata = textwrap.dedent(
            """
            import subprocess
            command = 'pwd'
            subprocess.call(command, shell=None)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(4, issue.lineno)
        self.assertEqual([4], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_system(self):
        fdata = textwrap.dedent(
            """
            import os
            os.system('/bin/echo hi')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_execl(self):
        fdata = textwrap.dedent(
            """
            import os
            os.execl(path, arg0, arg1)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_execle(self):
        fdata = textwrap.dedent(
            """
            import os
            os.execle(path, arg0, arg1, env)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_execlp(self):
        fdata = textwrap.dedent(
            """
            import os
            os.execlp(file, arg0, arg1)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_execlpe(self):
        fdata = textwrap.dedent(
            """
            import os
            os.execlpe(file, arg0, arg1, env)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_execv(self):
        fdata = textwrap.dedent(
            """
            import os
            os.execv(path, args)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_execve(self):
        fdata = textwrap.dedent(
            """
            import os
            os.execve(path, args, env)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_execvp(self):
        fdata = textwrap.dedent(
            """
            import os
            os.execvp(file, args)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_execvpe(self):
        fdata = textwrap.dedent(
            """
            import os
            os.execvpe(file, args, env)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_spawnl(self):
        fdata = textwrap.dedent(
            """
            import os
            os.spawnl(mode, path)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_spawnle(self):
        fdata = textwrap.dedent(
            """
            import os
            os.spawnle(mode, path, env)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_spawnlp(self):
        fdata = textwrap.dedent(
            """
            import os
            os.spawnlp(mode, file)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_spawnlpe(self):
        fdata = textwrap.dedent(
            """
            import os
            os.spawnlpe(mode, file, env)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_spawnv(self):
        fdata = textwrap.dedent(
            """
            import os
            os.spawnv(mode, path, args)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_spawnve(self):
        fdata = textwrap.dedent(
            """
            import os
            os.spawnve(mode, path, args, env)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_spawnvp(self):
        fdata = textwrap.dedent(
            """
            import os
            os.spawnvp(mode, file, args)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_spawnvpe(self):
        fdata = textwrap.dedent(
            """
            import os
            os.spawnvpe(mode, file, args, env)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_startfile_foo(self):
        fdata = textwrap.dedent(
            """
            import os
            os.startfile('/bin/foo.docx')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_startfile_bad(self):
        fdata = textwrap.dedent(
            """
            import os
            os.startfile('/bin/bad.exe')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_startfile_text(self):
        fdata = textwrap.dedent(
            """
            import os
            os.startfile('/bin/text.txt')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B606", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.MEDIUM, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_popen_uname(self):
        fdata = textwrap.dedent(
            """
            import os
            os.popen('/bin/uname -av')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_popen_uname(self):
        fdata = textwrap.dedent(
            """
            from os import popen
            popen('/bin/uname -av')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_o_popen_uname(self):
        fdata = textwrap.dedent(
            """
            import os as o
            o.popen('/bin/uname -av')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pos_uname(self):
        fdata = textwrap.dedent(
            """
            from os import popen as pos
            pos('/bin/uname -av')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_popen2_uname(self):
        fdata = textwrap.dedent(
            """
            import os
            os.popen2('/bin/uname -av')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_popen3_uname(self):
        fdata = textwrap.dedent(
            """
            import os
            os.popen3('/bin/uname -av')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_popen4_uname(self):
        fdata = textwrap.dedent(
            """
            import os
            os.popen4('/bin/uname -av')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_popen4_uname_rm(self):
        fdata = textwrap.dedent(
            """
            import os
            os.popen4('/bin/uname -av; rm -rf /')
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_os_popen4_some_var(self):
        fdata = textwrap.dedent(
            """
            import os
            os.popen4(some_var)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.HIGH, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pop_gcc_partial_path(self):
        fdata = textwrap.dedent(
            """
            from subprocess import Popen as pop
            pop('gcc --version', shell=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(2, len(self.visitor.tester.results))
        issue1 = self.visitor.tester.results[0]
        self.assertEqual("B607", issue1.test_id)
        self.assertEqual(bandit.LOW, issue1.severity)
        self.assertEqual(bandit.HIGH, issue1.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue1.cwe.id)
        self.assertEqual(3, issue1.lineno)
        self.assertEqual([3], issue1.linerange)
        self.assertEqual(0, issue1.col_offset)
        issue2 = self.visitor.tester.results[1]
        self.assertEqual("B603", issue2.test_id)
        self.assertEqual(bandit.LOW, issue2.severity)
        self.assertEqual(bandit.HIGH, issue2.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue2.cwe.id)
        self.assertEqual(3, issue2.lineno)
        self.assertEqual([3], issue2.linerange)
        self.assertEqual(0, issue2.col_offset)

    def test_pop_gcc_absolute_path(self):
        fdata = textwrap.dedent(
            """
            from subprocess import Popen as pop
            pop('/bin/gcc --version', shell=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pop_var_shell_false(self):
        fdata = textwrap.dedent(
            """
            from subprocess import Popen as pop
            pop(var, shell=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pop_partial_path_arg_list_shell_false(self):
        fdata = textwrap.dedent(
            """
            from subprocess import Popen as pop
            pop(['ls', '-l'], shell=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(2, len(self.visitor.tester.results))
        issue1 = self.visitor.tester.results[0]
        self.assertEqual("B607", issue1.test_id)
        self.assertEqual(bandit.LOW, issue1.severity)
        self.assertEqual(bandit.HIGH, issue1.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue1.cwe.id)
        self.assertEqual(3, issue1.lineno)
        self.assertEqual([3], issue1.linerange)
        self.assertEqual(0, issue1.col_offset)
        issue2 = self.visitor.tester.results[1]
        self.assertEqual("B603", issue2.test_id)
        self.assertEqual(bandit.LOW, issue2.severity)
        self.assertEqual(bandit.HIGH, issue2.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue2.cwe.id)
        self.assertEqual(3, issue2.lineno)
        self.assertEqual([3], issue2.linerange)
        self.assertEqual(0, issue2.col_offset)

    def test_pop_absolute_path_arg_list_shell_false(self):
        fdata = textwrap.dedent(
            """
            from subprocess import Popen as pop
            pop(['/bin/ls', '-l'], shell=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pop_ls_shell_false(self):
        fdata = textwrap.dedent(
            """
            from subprocess import Popen as pop
            pop('../ls -l', shell=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pop_windows_path_shell_false(self):
        fdata = textwrap.dedent(
            """
            from subprocess import Popen as pop
            pop('c:\\hello\\something', shell=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_pop_linux_path_shell_false(self):
        fdata = textwrap.dedent(
            """
            from subprocess import Popen as pop
            pop('c:/hello/something_else', shell=False)
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B603", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(0, issue.col_offset)

    def test_commands_getstatusoutput(self):
        fdata = textwrap.dedent(
            """
            import commands
            print(commands.getstatusoutput('/bin/echo / | xargs ls'))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(6, issue.col_offset)

    def test_commands_getoutput(self):
        fdata = textwrap.dedent(
            """
            import commands
            print(commands.getoutput('/bin/echo / | xargs ls'))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(6, issue.col_offset)

    def test_commands_getstatus(self):
        fdata = textwrap.dedent(
            """
            import commands
            print(commands.getstatus('/bin/echo / | xargs ls'))
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(0, len(self.visitor.tester.results))

    def test_popen2_popen2(self):
        fdata = textwrap.dedent(
            """
            import popen2
            print(popen2.popen2('/bin/echo / | xargs ls')[0].read())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(6, issue.col_offset)

    def test_popen2_popen3(self):
        fdata = textwrap.dedent(
            """
            import popen2
            print(popen2.popen3('/bin/echo / | xargs ls')[0].read())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(6, issue.col_offset)

    def test_popen2_popen4(self):
        fdata = textwrap.dedent(
            """
            import popen2
            print(popen2.popen4('/bin/echo / | xargs ls')[0].read())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(6, issue.col_offset)

    def test_popen2_popen3_fromchild_read(self):
        fdata = textwrap.dedent(
            """
            import popen2
            print(popen2.Popen3('/bin/echo / | xargs ls').fromchild.read())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(6, issue.col_offset)

    def test_popen2_popen4_fromchild_read(self):
        fdata = textwrap.dedent(
            """
            import popen2
            print(popen2.Popen3('/bin/echo / | xargs ls').fromchild.read())
            """
        )
        self.visitor.process(fdata)
        self.assertEqual(1, len(self.visitor.tester.results))
        issue = self.visitor.tester.results[0]
        self.assertEqual("B605", issue.test_id)
        self.assertEqual(bandit.LOW, issue.severity)
        self.assertEqual(bandit.HIGH, issue.confidence)
        self.assertEqual(b_issue.Cwe.OS_COMMAND_INJECTION, issue.cwe.id)
        self.assertEqual(3, issue.lineno)
        self.assertEqual([3], issue.linerange)
        self.assertEqual(6, issue.col_offset)
