# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
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
import ast

import constants


def severity(func, severity):
    '''Decorator function to set 'severity' attribute.'''
    if severity not in constants.SEVERITY_LEVEL._fields:
        raise TypeError("severity error: %s is not one of %s." % (severity,
                        ",".join(constants.SEVERITY_LEVEL._fields)))
    func._severity = severity
    return func


def confidence(func, conf):
    '''Decorator function to set 'confidence' attribute.'''
    if conf not in constants.CONFIDENCE_LEVEL:
        raise TypeError("Confidence error: %s is not one of %s." % (conf,
                        ",".join(constants.CONFIDENCE_LEVEL)))
    func._conf = conf
    return func


def category(func, category):
    '''Decorator function to set 'category'.'''
    func._category = category
    return func


def title(func, title):
    '''Decorator function to set 'title' attribute.'''
    func._title = title
    return func


def uuid(func, uuid):
    '''Decorator function to set 'uuid' attribute.'''
    func._uuid = uuid
    return func


def checks(func, *args):
    '''Decorator function to set checks to be run.'''
    if not hasattr(func, "_checks"):
        func._checks = []
    for a in args:
        holder = getattr(ast, a)
        if holder and issubclass(holder, ast.stmt):
            func._checks.append(a)
        else:
            raise TypeError("Error: %s is not a valid node type in AST" % a)
    return func


def checks_functions(func):
    '''Test function checks function definitions

    Use of this delegate before a test function indicates that it should be
    called any time a function definition is encountered.
    '''
    if not hasattr(func, "_checks"):
        func._checks = []
    func._checks.append("functions")
    return func


def checks_calls(func):
    '''Test function checks function calls

    Use of this delegate before a test function indicates that it should be
    called any time a function call is encountered.
    '''
    if not hasattr(func, "_checks"):
        func._checks = []
    func._checks.append("calls")
    return func


def checks_imports(func):
    '''Test function checks imports

    Use of this delegate before a test function indicates that it should be
    called any time an import is encountered.
    '''
    if not hasattr(func, "_checks"):
        func._checks = []
    func._checks.append("imports")
    return func


def checks_strings(func):
    '''Test function checks strings

    Use of this delegate before a test function indicates that it should be
    called any time a string value is encountered.
    '''
    if not hasattr(func, "_checks"):
        func._checks = []
    func._checks.append("strings")
    return func


def checks_exec(func):
    '''Test function checks exec nodes

    Use of this delegate before a test function indicates that it should be
    called any time the 'exec' statement is encountered.
    '''
    if not hasattr(func, "_checks"):
        func._checks = []
    func._checks.append("exec")
    return func


def takes_config(*args):
    '''Test function takes config

    Use of this delegate before a test function indicates that it should be
    passed data from the config file. Passing a name parameter allows
    aliasing tests and thus sharing config options.
    '''
    name = ""

    def _takes_config(func):
        if not hasattr(func, "_takes_config"):
            func._takes_config = name
        return func

    if len(args) == 1 and callable(args[0]):
        name = args[0].__name__
        return _takes_config(args[0])
    else:
        name = args[0]
        return _takes_config
