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

import stat

import bandit
from bandit.core.test_properties import *


@checks('Call')
def set_bad_file_permissions(context):
    if 'chmod' in context.call_function_name:
        if context.call_args_count == 2:
            mode = context.get_call_arg_at_position(1)

            if (
                mode is not None and type(mode) == int and
                (mode & stat.S_IWOTH or mode & stat.S_IXGRP)
            ):
                # world writable is an HIGH, group executable is a MEDIUM
                if mode & stat.S_IWOTH:
                    sev_level = bandit.HIGH
                else:
                    sev_level = bandit.MEDIUM

                filename = context.get_call_arg_at_position(0)
                if filename is None:
                    filename = 'NOT PARSED'
                return bandit.Issue(
                    severity=sev_level,
                    confidence=bandit.HIGH,
                    text="Chmod setting a permissive mask %s on file (%s)." %
                         (oct(mode), filename)
                )
