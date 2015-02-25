# Copyright (c) 2015 VMware, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import bandit
from bandit.core.test_properties import *


@takes_config
@checks('Call')
def password_config_option_not_marked_secret(context, config):

    if (context.call_function_name_qual in config['function_names']):
        if context.get_call_arg_at_position(0).endswith('password'):
            # Checks whether secret=False or secret is not set (None).
            if (context.check_call_arg_value('secret') in
                    constants.FALSE_VALUES):
                return(bandit.WARN, 'oslo config option not marked secret=True'
                       ' identified, security issue.  %s' %
                       context.call_args_string)
            # Checks whether secret is not True, for example when its set to a
            # variable, secret=secret.
            elif context.check_call_arg_value('secret') != 'True':
                return(bandit.INFO, 'oslo config option possibly not marked'
                       ' secret=True identified.  %s' %
                       context.call_args_string)
