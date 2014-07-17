#!/usr/bin/env python

from collections import OrderedDict
import utils
import _ast
import stat


class BanditTestSet():

    tests = OrderedDict()

    # stubbed tests
    def _test_import_name_match(self, context):
        info_on_import = ['pickle', 'subprocess', 'Crypto']
        for module in info_on_import:
            if context['module'] == module:
                return('INFO',
                       "Consider possible security implications"
                       " associated with '%s' module" % module)

    def _test_call_bad_names(self, context):
        bad_name_sets = [
            (['pickle.loads', 'pickle.dumps', ],
             'Pickle library appears to be in use, possible security issue.'),
            (['hashlib.md5', ],
             'Use of insecure MD5 hash function.'),
            (['subprocess.Popen', ],
             'Use of possibly-insecure system call function '
             '(subprocess.Popen).'),
            (['subprocess.call', ],
             'Use of possibly-insecure system call function '
             '(subprocess.call).'),
            (['mktemp', ],
             'Use of insecure and deprecated function (mktemp).'),
            (['eval', ],
             'Use of possibly-insecure function - consider using the safer '
             'ast.literal_eval().'),
        ]

        # test for 'bad' names defined above
        for bad_name_set in bad_name_sets:
            for bad_name in bad_name_set[0]:
                # if name.startswith(bad_name) or name.endswith(bad_name):
                if context['qualname'] == bad_name:
                    return('WARN', "%s  %s" %
                           (bad_name_set[1],
                            utils.ast_args_to_str(context['call'].args)))

    def _test_call_subprocess_popen(self, context):
        if context['qualname'] == 'subprocess.Popen':
            if hasattr(context['call'], 'keywords'):
                for k in context['call'].keywords:
                    if k.arg == 'shell' and isinstance(k.value, _ast.Name):
                        if k.value.id == 'True':
                            return('ERROR', 'Popen call with shell=True '
                                   'identified, security issue.  %s' %
                                   utils.ast_args_to_str(context['call'].args))

    def _test_call_no_cert_validation(self, context):
        if 'requests' in context['qualname'] and ('get' in context['name'] or
                                              'post' in context['name']):
            if hasattr(context['call'], 'keywords'):
                for k in context['call'].keywords:
                    if k.arg == 'verify' and isinstance(k.value, _ast.Name):
                        if k.value.id == 'False':
                            return('ERROR',
                                   'Requests call with verify=False '
                                   'disabling SSL certificate checks, '
                                   'security issue.   %s' %
                                   utils.ast_args_to_str(context['call'].args))

    def _test_call_bad_permissions(self, context):
        if 'chmod' in context['name']:
            if (hasattr(context['call'], 'args')):
                args = context['call'].args
                if len(args) == 2 and isinstance(args[1],  _ast.Num):
                    if ((args[1].n & stat.S_IWOTH) or
                       (args[1].n & stat.S_IXGRP)):
                        return('ERROR',
                               'Chmod setting a permissive mask '
                               '%s on file (%s).' %
                               (oct(args[1].n), args[0].s))

# end stubbed tests

    def __init__(self, logger):
        self.logger = logger
        self.load_tests()

    def load_tests(self):
        # each test should have a name, target node/s, and function...
        # for now, stub in some tests
        self.tests['import_name_match'] = {
            'targets': ['Import', 'ImportFrom'],
            'function': self._test_import_name_match}
        self.tests['call_bad_names'] = {
            'targets': ['Call', ],
            'function': self._test_call_bad_names}
        self.tests['call_subprocess_popen'] = {
            'targets': ['Call', ],
            'function': self._test_call_subprocess_popen}
        self.tests['call_no_cert_validation'] = {
            'targets': ['Call', ],
            'function': self._test_call_no_cert_validation}
        self.tests['call_bad_permissions'] = {
            'targets': ['Call', ],
            'function': self._test_call_bad_permissions}

    def get_tests(self, nodetype):
        self.logger.debug('get_tests called with nodetype: %s' % nodetype)
        scoped_tests = {}
        for test in self.tests:
            if nodetype in self.tests[test]['targets']:
                scoped_tests[test] = self.tests[test]
        self.logger.debug('get_tests returning scoped_tests : %s' %
                          scoped_tests)
        return scoped_tests
