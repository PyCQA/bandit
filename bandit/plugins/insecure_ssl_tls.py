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

import bandit
from bandit.core.test_properties import *


def get_bad_proto_versions(config):
    return config['bad_protocol_versions']


@takes_config
@checks('Call')
def ssl_with_bad_version(context, config):
    bad_ssl_versions = get_bad_proto_versions(config)
    if (context.call_function_name_qual == 'ssl.wrap_socket'):
        if context.check_call_arg_value('ssl_version', bad_ssl_versions):
            return bandit.Issue(
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text="ssl.wrap_socket call with insecure SSL/TLS protocol "
                     "version identified, security issue."
            )
    elif (context.call_function_name_qual == 'pyOpenSSL.SSL.Context'):
        if context.check_call_arg_value('method', bad_ssl_versions):
            return bandit.Issue(
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                text="SSL.Context call with insecure SSL/TLS protocol "
                     "version identified, security issue."
            )

    elif (context.call_function_name_qual != 'ssl.wrap_socket' and
          context.call_function_name_qual != 'pyOpenSSL.SSL.Context'):
        if (context.check_call_arg_value('method', bad_ssl_versions) or
           context.check_call_arg_value('ssl_version', bad_ssl_versions)):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                text="Function call with insecure SSL/TLS protocol "
                     "identified, possible security issue."
            )


@takes_config("ssl_with_bad_version")
@checks('FunctionDef')
def ssl_with_bad_defaults(context, config):
    bad_ssl_versions = get_bad_proto_versions(config)
    for default in context.function_def_defaults_qual:
        val = default.split(".")[-1]
        if val in bad_ssl_versions:
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                text="Function definition identified with insecure SSL/TLS "
                     "protocol version by default, possible security "
                     "issue."
            )


@checks('Call')
def ssl_with_no_version(context):
    if (context.call_function_name_qual == 'ssl.wrap_socket'):
        if context.check_call_arg_value('ssl_version') is None:
            # check_call_arg_value() returns False if the argument is found
            # but does not match the supplied value (or the default None).
            # It returns None if the arg_name passed doesn't exist. This
            # tests for that (ssl_version is not specified).
            return bandit.Issue(
                severity=bandit.LOW,
                confidence=bandit.MEDIUM,
                text="ssl.wrap_socket call with no SSL/TLS protocol version "
                     "specified, the default SSLv23 could be insecure, "
                     "possible security issue."
            )
