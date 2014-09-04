# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import bandit
import re
from bandit.test_selector import *

@checks_functions
def call_bad_names(context):
    # TODO - move this out into configuration
    bad_name_sets = [
        (['pickle\.((loads)|(dumps))', ],
         'Pickle library appears to be in use, possible security issue.'),
        (['hashlib\.md5', ],
         'Use of insecure MD5 hash function.'),
        (['subprocess\.Popen', ],
         'Use of possibly-insecure system call function '
         '(subprocess.Popen).'),
        (['subprocess\.call', ],
         'Use of possibly-insecure system call function '
         '(subprocess.call).'),
        (['os.((exec)|(spawn))((l)|(le)|(lp)|(lpe)|(v)|(ve)|(vp)|(vpe))', ],
         'Use of possibly-insecure system call function '
         '(os.exec* or os.spawn*).'),
        (['os.popen((2)|(3)|(4))*', 'popen'],
         'Use of insecure / deprecated system call function '
         '(os.popen).'),
        (['os.startfile', 'startfile'],
         'Use of insecure system function (os.startfile).'),
        (['tempfile\.mktemp', 'mktemp'],
         'Use of insecure and deprecated function (mktemp).'),
        (['eval', ],
         'Use of possibly-insecure function - consider using the safer '
         'ast.literal_eval().'),
        (['mark_safe', ],
         'Use of mark_safe() may expose cross-site scripting vulnerabilities '
         'and should be reviewed.'),
    ]

    # test for 'bad' names defined above
    for bad_name_set in bad_name_sets:
        for bad_name_regex in bad_name_set[0]:
            # various tests we could do here, re.match works for now
            if re.match(bad_name_regex, context.call_function_name_qual):
                return(bandit.WARN, "%s  %s" %
                       (bad_name_set[1],
                        context.call_args_string))
