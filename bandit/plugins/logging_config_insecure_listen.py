# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0

r"""
====================================================
B612: Test for insecure use of logging.config.listen
====================================================

This plugin test checks for the unsafe usage of the
``logging.config.listen`` function. The logging.config.listen
function provides the ability to listen for external
configuration files on a socket server. Because portions of the
configuration  are passed through eval(), use of this function
may open its users to a security risk. While the function only
binds to a socket on localhost, and so does not accept connections
from remote machines, there are scenarios where untrusted code
could be run under the account of the process which calls listen().

logging.config.listen provides the ability to verify bytes received
across the socket with signature verification or encryption/decryption.

:Example:
    >> Issue: [B612:logging_config_listen] Use of insecure
    logging.config.listen detected.
       Severity: Medium   Confidence: High
       Location: examples/logging_config_insecure_listen.py:3:4
    2
    3	t = logging.config.listen(9999)

.. versionadded:: 1.7.4

"""

import bandit
from bandit.core import test_properties as test


@test.checks('Call')
@test.test_id('B612')
def logging_config_insecure_listen(context):
    if context.call_function_name_qual == 'logging.config.listen' \
            and 'verify' not in context.call_keywords:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            text="Use of insecure logging.config.listen detected."
        )
