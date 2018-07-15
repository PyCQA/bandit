# -*- coding:utf-8 -*-
#
# Copyright (c) Victor Torre 2018
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
from bandit.core import test_properties as test


@test.checks('Call')
@test.test_id('B301')
def read_gpickle_used(context):
    description = "B301 + networkx.read_gpickle"
    picklet_funct = [
        'pickle.loads',
        'pickle.load',
        'pickle.Unpickler',
        'cPickle.loads',
        'cPickle.load',
        'cPickle.Unpickler',
        'networkx.read_gpickle'
    ]
    if context.call_function_name_qual in picklet_funct:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            text=description
        )
