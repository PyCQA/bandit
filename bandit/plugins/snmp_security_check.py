# -*- coding:utf-8 -*-
#
# Copyright (c) 2018 SolarWinds, Inc.
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


@test.checks("Call")
@test.test_id('B508')
def snmp_insecure_version_check(context):
    r"""
    -----------------------------
    B508: snmp_insecure_version
    -----------------------------

    This test is for checking for the usage of insecure SNMP version such as:
      v1, v2c and v3 using noAuthNoPriv.

    Using the pysnmp documentation:
      http://snmplabs.com/pysnmp/examples/hlapi/asyncore/sync/manager/cmdgen/snmp-versions.html

    Please update your code to use more secure versions of SNMP. For example:

    Instead of:
      `CommunityData('public', mpModel=0)`

    Use (Defaults to usmHMACMD5AuthProtocol and usmDESPrivProtocol
      `UsmUserData("securityName","authName","privName")`
    """
    if context.call_function_name_qual == 'CommunityData':
        # We called community data. Lets check our args
        if context.check_call_arg_value("mpModel", 0) or \
                context.check_call_arg_value("mpModel", 1):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                text="The use of SNMPv1 and SNMPv2 is insecure. "
                     "You should use SNMPv3 if able.",
                lineno=context.get_lineno_for_call_arg("CommunityData"),
            )


@test.checks("Call")
@test.test_id('B509')
def snmp_crypto_check(context):
    r"""
    -----------------------------
    B509: snmp_weak_cryptography
    -----------------------------

    This test is for checking for the usage of insecure SNMP cryptography such as:
      v3 using noAuthNoPriv.

    Using the pysnmp documentation:
      http://snmplabs.com/pysnmp/examples/hlapi/asyncore/sync/manager/cmdgen/snmp-versions.html

    Please update your code to use more secure versions of SNMP. For example:

    Instead of:
      `CommunityData('public', mpModel=0)`

    Use (Defaults to usmHMACMD5AuthProtocol and usmDESPrivProtocol
      `UsmUserData("securityName","authName","privName")`
    """
    if context.call_function_name_qual == 'UsmUserData':
        if context.call_args_count == 1 or context.call_args_count == 1:
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                text="You should not use SNMPv3 without encryption. "
                     "noAuthNoPriv is an insecure method of transport.",
                lineno=context.get_lineno_for_call_arg("UsmUserData"),
            )
