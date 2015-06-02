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
import logging

from bandit.core import constants

logger = logging.getLogger()


def severity(sev):
    '''Decorator function to set 'severity' property.'''
    def wrapper(func):
        if sev not in constants.SEVERITY_LEVEL._fields:
            raise TypeError("Severity error: %s is not one of %s." % (sev,
                            ",".join(constants.SEVERITY_LEVEL._fields)))
        func._severity = sev
        return func
    return wrapper


def category(new_category):
    '''Decorator function to set 'category'.'''
    def wrapper(func):
        func._category = new_category
        return func
    return wrapper


def title(new_title):
    '''Decorator function to set 'title' property.'''
    def wrapper(func):
        func._title = new_title
        return func
    return wrapper


def uuid(new_uuid):
    '''Decorator function to set 'uuid' property.'''
    def wrapper(func):
        func._uuid = uuid
        return func
    return wrapper


def checks(*args):
    '''Decorator function to set checks to be run.'''
    def wrapper(func):
        if not hasattr(func, "_checks"):
            func._checks = []
        for a in args:
            try:
                holder = getattr(ast, a)
            except AttributeError:
                raise TypeError(
                    "Error: %s is not a valid node type in AST" % a
                )
            else:
                if holder and issubclass(holder, ast.AST):
                    func._checks.append(a)
                else:
                    raise TypeError(
                        "Error: %s is not a valid node type in AST" % a
                    )
        logger.debug('checks() decorator executed')
        logger.debug('  func._checks: %s', func._checks)
        return func
    return wrapper


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
