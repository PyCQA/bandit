
import ast
import unittest
from unittest import mock

import bandit
from bandit.core import issue
from bandit.plugins import injection_shell

class InjectionShellTests(unittest.TestCase):

    def _get_context(self, function_name, args=None, keywords=None):
        context = mock.Mock()
        context.call_function_name_qual = function_name
        # context.call_args expects a list of arguments passed to the function call
        context.call_args = args or []
        context.call_keywords = keywords or {}
        context.node = mock.Mock()
        context.node.args = []
        context.node.keywords = []
        # Helpers for getting line number
        context.get_lineno_for_call_arg.return_value = 1
        return context

    def test_subprocess_popen_with_shell_true_low_severity(self):
        # Case: subprocess.Popen('ls', shell=True) -> LOW severity (static string)
        context = self._get_context('subprocess.Popen', args=[mock.Mock()], keywords={'shell': True})
        
        # Mocking context.node for _evaluate_shell_call
        # It checks if args[0] is ast.Constant and value is str
        arg_node = ast.Constant(value='ls')
        context.node.args = [arg_node]
        
        config = {'subprocess': ['subprocess.Popen']}
        
        with mock.patch('bandit.plugins.injection_shell.has_shell', return_value=True):
            result = injection_shell.subprocess_popen_with_shell_equals_true(context, config)
            
        self.assertIsInstance(result, bandit.Issue)
        self.assertEqual(bandit.LOW, result.severity)
        self.assertEqual(bandit.HIGH, result.confidence)
        self.assertEqual("call with shell=True", "call with shell=True") # Dummy assertion

    def test_subprocess_popen_with_shell_true_high_severity(self):
        # Case: subprocess.Popen(cmd, shell=True) -> HIGH severity (dynamic)
        context = self._get_context('subprocess.Popen', args=[mock.Mock()], keywords={'shell': True})
        
        # Mocking context.node for _evaluate_shell_call
        # It checks if args[0] is ast.Constant. If not (e.g. ast.Name), it returns HIGH.
        arg_node = ast.Name(id='cmd', ctx=ast.Load())
        context.node.args = [arg_node]
        
        config = {'subprocess': ['subprocess.Popen']}
        
        with mock.patch('bandit.plugins.injection_shell.has_shell', return_value=True):
            result = injection_shell.subprocess_popen_with_shell_equals_true(context, config)
            
        self.assertIsInstance(result, bandit.Issue)
        self.assertEqual(bandit.HIGH, result.severity)
        self.assertEqual(bandit.HIGH, result.confidence)

    def test_subprocess_without_shell_equals_true(self):
        # Case: subprocess.Popen(['ls'], shell=False) -> LOW severity
        context = self._get_context('subprocess.Popen', args=[mock.Mock()])
        config = {'subprocess': ['subprocess.Popen']}
        
        with mock.patch('bandit.plugins.injection_shell.has_shell', return_value=False):
            result = injection_shell.subprocess_without_shell_equals_true(context, config)
            
        self.assertIsInstance(result, bandit.Issue)
        self.assertEqual(bandit.LOW, result.severity)
        self.assertEqual(bandit.HIGH, result.confidence)
        self.assertIn("subprocess call - check for execution of untrusted input", result.text)

    def test_any_other_function_with_shell_equals_true(self):
        # Case: custom_function(cmd, shell=True) -> MEDIUM severity
        context = self._get_context('custom_function', args=[mock.Mock()], keywords={'shell': True})
        config = {'subprocess': ['subprocess.Popen']}
        
        with mock.patch('bandit.plugins.injection_shell.has_shell', return_value=True):
            result = injection_shell.any_other_function_with_shell_equals_true(context, config)
            
        self.assertIsInstance(result, bandit.Issue)
        self.assertEqual(bandit.MEDIUM, result.severity)
        self.assertEqual(bandit.LOW, result.confidence)

    def test_start_process_with_a_shell(self):
        # Case: os.system('ls') -> LOW or HIGH depending on input
        # LOW if static
        context = self._get_context('os.system', args=[mock.Mock()])
        arg_node = ast.Constant(value='ls')
        context.node.args = [arg_node]
        
        config = {'shell': ['os.system']}
        
        result = injection_shell.start_process_with_a_shell(context, config)
        
        self.assertIsInstance(result, bandit.Issue)
        self.assertEqual(bandit.LOW, result.severity)
        
        # HIGH if dynamic
        context_dynamic = self._get_context('os.system', args=[mock.Mock()])
        arg_node_dynamic = ast.Name(id='cmd', ctx=ast.Load())
        context_dynamic.node.args = [arg_node_dynamic]
        
        result_dynamic = injection_shell.start_process_with_a_shell(context_dynamic, config)
        self.assertEqual(bandit.HIGH, result_dynamic.severity)

    def test_start_process_with_no_shell(self):
        # Case: os.execl(...) -> LOW severity
        context = self._get_context('os.execl')
        config = {'no_shell': ['os.execl']}
        
        result = injection_shell.start_process_with_no_shell(context, config)
        
        self.assertIsInstance(result, bandit.Issue)
        self.assertEqual(bandit.LOW, result.severity)

