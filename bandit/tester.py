#!/usr/bin/env python

import ast, _ast
import stat

class BanditTester():

    results = None

    def __init__(self, logger, results):
        self.logger = logger
        self.results = results
        self.last_result = None

    def _ast_args_to_str(self, args):
        res = '\n\tArgument/s:\n\t\t%s' % '\n\t\t'.join([ast.dump(arg) for arg in args])
        res = ''
        return res

    def test_call(self, call, name=None):
        self.logger.debug("test_call (%s) executed with Call object: %s" % (name, ast.dump(call)))
        return False

    def test_call_with_name(self, file_detail, name, call, imports, aliases):
        self.logger.debug('test_call_name executed with name : %s' % name) 
        self.logger.debug('test_call_name    callobj : %s' % ast.dump(call))
        self.logger.debug('test_call_name    imports : %s' % imports)
        self.logger.debug('test_call_name    aliases : %s' % aliases)
        bad_name_sets = [
            (   ['pickle.loads', 'pickle.dumps',],
                'Pickle library appears to be in use, possible security issue.'),
            (   ['hashlib.md5',],
                'Use of insecure MD5 hash function.'),
            (   ['subprocess.Popen',],
                'Use of possibly-insecure system call function (subprocess.Popen).'),
            (   ['subprocess.call',],
                'Use of possibly-insecure system call function (subprocess.call).'),
            (   ['mktemp',],
                'Use of insecure and deprecated function (mktemp).'),
            (   ['eval',],
                'Use of possibly-insecure function - consider using the safer ast.literal_eval().'),
        ]
        #subs in import aliases
        if name in aliases:
            name = aliases[name]
        else:
            for alias in aliases:
                if name != None and name.startswith('%s.' % alias):
                    name = "%s.%s" % (aliases[alias], name[len(alias) + 1:])

        #do tests
        if name != None:
            #specific tests based on function names
            #if 'Popen' in name:
            if name == 'subprocess.Popen':
                if hasattr(call, 'keywords'):
                    for k in call.keywords:
                        if k.arg == 'shell' and isinstance(k.value, _ast.Name):
                            if k.value.id == 'True':
                                self.results.add(file_detail, 'ERROR', 'Popen call with shell=True identified, security issue.  %s' % self._ast_args_to_str(call.args))
            if 'requests' in name and ('get' in name or 'post' in name):
                if hasattr(call, 'keywords'):
                    for k in call.keywords:
                        if k.arg == 'verify' and isinstance(k.value, _ast.Name):
                            if k.value.id == 'False':
                                self.results.add(file_detail, 'ERROR', 'Requests call with verify=False disabling SSL certificate checks, security issue.  %s' % self._ast_args_to_str(call.args))


            if 'chmod' in name :
                if hasattr(call, 'args') and len(call.args) == 2:
                    if isinstance(call.args[1], _ast.Num):
                        if (call.args[1].n & stat.S_IWOTH) or (call.args[1].n & stat.S_IXGRP):
                            try:
                                self.results.add(file_detail, 'ERROR', 'Chmod setting a permissive mask %s on file (%s).' % (oct(call.args[1].n), call.args[0].s))
                            except AttributeError:
                                self.results.add(file_detail, 'ERROR', 'Chmod setting a permissive mask %s on file.' % (oct(call.args[1].n)))

            #test for 'bad' names defined above
            for bad_name_set in bad_name_sets:
                for bad_name in bad_name_set[0]:
                    #if name.startswith(bad_name) or name.endswith(bad_name):
                    if name == bad_name:
                        self.results.add(file_detail, 'WARN', "%s  %s" % (bad_name_set[1], self._ast_args_to_str(call.args)))


    def test_import_name(self, file_detail, name):
        self.logger.debug('test_import_name executed with name : %s' % name) 
        warn_on_import = ['pickle', 'subprocess', 'crypto']
        for mod in warn_on_import:
            if name.startswith(mod):
                self.results.add(file_detail, 'INFO', "Consider possible security implications associated with '%s' module" % mod)

