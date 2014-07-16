#!/usr/bin/env python

import ast, _ast
import stat
import utils

class BanditTester():

    results = None

    def __init__(self, logger, results, testset):
        self.logger = logger
        self.results = results
        self.testset = testset
        self.last_result = None

    # This should be a utility call available to tests
    def _ast_args_to_str(self, args):
        res = '\n\tArgument/s:\n\t\t%s' % '\n\t\t'.join([ast.dump(arg) for arg in args])
        res = ''
        return res

    def run_tests(node):
        for test in testset.get_tests():
            #check that test is valid for a node of this type
            print(ast.dump(node))
            #execute test with the relevant details to the current node
            test.run(file_detail, name, call, imports, aliases)

    def test_call(self, call, name=None):
        self.logger.debug("test_call (%s) executed with Call object: %s" % (name, ast.dump(call)))
        return False

    def test_call_with_name(self, file_detail, name, call, imports, aliases):
        self.logger.debug('test_call_name executed with name : %s' % name) 
        self.logger.debug('test_call_name    callobj : %s' % ast.dump(call))
        self.logger.debug('test_call_name    imports : %s' % imports)
        self.logger.debug('test_call_name    aliases : %s' % aliases)

        #subs in import aliases
        if name in aliases:
            name = aliases[name]
        else:
            for alias in aliases:
                if name != None and name.startswith('%s.' % alias):
                    name = "%s.%s" % (aliases[alias], name[len(alias) + 1:])

        self.test_call_bad_names(file_detail, name, call, imports, aliases,
                                 self.results)
        self.test_call_subprocess_popen(file_detail, name, call, imports,
                                        aliases, self.results)
        self.test_call_no_cert_validation(file_detail, name, call, imports,
                                          aliases, self.results)
        self.test_call_bad_permissions(file_detail, name, call, imports,
                                       aliases, self.results)

    def test_import_name(self, file_detail, name):
        self.logger.debug('test_import_name executed with name : %s' % name) 
        warn_on_import = ['pickle', 'subprocess', 'crypto']
        for mod in warn_on_import:
            if name.startswith(mod):
                self.results.add(file_detail, 'INFO', "Consider possible security implications associated with '%s' module" % mod)

    # Define actual tests here.  These should be extracted and used as plug-ins.
    def test_call_bad_names(self, file_detail, name, call, imports, aliases,
                            results):
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
                if name == bad_name:
                    results.add(file_detail, 'WARN', "%s  %s" %
                                (bad_name_set[1],
                                 utils.ast_args_to_str(call.args)))

    def test_call_subprocess_popen(self, file_detail, name, call, imports,
                                   aliases, results):
        if name is not None and name == 'subprocess.Popen':
            if hasattr(call, 'keywords'):
                for k in call.keywords:
                    if k.arg == 'shell' and isinstance(k.value, _ast.Name):
                        if k.value.id == 'True':
                            results.add(file_detail, 'ERROR', 'Popen call '
                                        'with shell=True identified, security '
                                        'issue.  %s' %
                                        utils.ast_args_to_str(call.args))

    def test_call_no_cert_validation(self, file_detail, name, call, imports,
                                     aliases, results):
        if name is not None and 'requests' in name and ('get' in name or
                                                        'post' in name):
            if hasattr(call, 'keywords'):
                for k in call.keywords:
                    if k.arg == 'verify' and isinstance(k.value, _ast.Name):
                        if k.value.id == 'False':
                            results.add(file_detail, 'ERROR',
                                        'Requests call with verify=False '
                                        'disabling SSL certificate checks, '
                                        'security issue.   %s' %
                                        utils.ast_args_to_str(call.args))

    def test_call_bad_permissions(self, file_detail, name, call, imports,
                                  aliases, results):
        if name is not None and 'chmod' in name:
                if hasattr(call, 'args') and len(call.args) == 2:
                    if isinstance(call.args[1], _ast.Num):
                        if ((call.args[1].n & stat.S_IWOTH) or
                           (call.args[1].n & stat.S_IXGRP)):
                            try:
                                results.add(file_detail, 'ERROR',
                                            'Chmod setting a permissive mask '
                                            '%s on file (%s).' %
                                            (oct(call.args[1].n),
                                             call.args[0].s))
                            except AttributeError:
                                results.add(file_detail, 'ERROR',
                                            'Chmod setting a permissive mask '
                                            '%s on file.' %
                                            (oct(call.args[1].n)))
