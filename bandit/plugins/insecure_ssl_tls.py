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
        if context.check_call_arg_value('ssl_version') in bad_ssl_versions:

            return(bandit.ERROR, 'ssl.wrap_socket call with insecure SSL/TLS'
                   ' protocol version identified, security issue.  %s' %
                   context.call_args_string)
    elif (context.call_function_name_qual == 'pyOpenSSL.SSL.Context'):
        if context.check_call_arg_value('method') in bad_ssl_versions:

            return(bandit.ERROR, 'SSL.Context call with insecure SSL/TLS'
                   ' protocol version identified, security issue.  %s' %
                   context.call_args_string)

    elif (context.call_function_name_qual != 'ssl.wrap_socket' and
          context.call_function_name_qual != 'pyOpenSSL.SSL.Context'):
        if (context.check_call_arg_value('method') in bad_ssl_versions or
           context.check_call_arg_value('ssl_version') in bad_ssl_versions):

            return(bandit.WARN, 'Function call with insecure SSL/TLS '
                   'protocol identified, possible security issue.  %s' %
                   context.call_args_string)


@takes_config("ssl_with_bad_version")
@checks('FunctionDef')
def ssl_with_bad_defaults(context, config):
    bad_ssl_versions = get_bad_proto_versions(config)
    for default in context.function_def_defaults_qual:
        val = default.split(".")[-1]
        if val in bad_ssl_versions:
            return(bandit.WARN, 'function definition identified with insecure'
                   ' SSL/TLS protocol version by default, possible security'
                   ' issue.  %s' %
                   context.call_args_string)


@checks('Call')
def ssl_with_no_version(context):
    if (context.call_function_name_qual == 'ssl.wrap_socket'):
        if context.check_call_arg_value('ssl_version') is None:

            return(bandit.INFO, 'ssl.wrap_socket call with no SSL/TLS'
                   ' protocol version specified, the default SSLv23 could be'
                   ' insecure, possible security issue.  %s' %
                   context.call_args_string)
