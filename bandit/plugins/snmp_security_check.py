#
# Copyright (c) 2018 SolarWinds, Inc.
#
# SPDX-License-Identifier: Apache-2.0
import bandit
from bandit.core import test_properties as test


@test.checks("Call")
@test.test_id("B508")
def snmp_insecure_version_check(context):
    """**B508: Checking for insecure SNMP versions**

    This test is for checking for the usage of insecure SNMP version like
      v1, v2c

    Using the pysnmp documentation:
      http://snmplabs.com/pysnmp/examples/hlapi/asyncore/sync/manager/cmdgen/snmp-versions.html

    Please update your code to use more secure versions of SNMP.

    .. versionadded:: 1.7.2
    """

    if context.call_function_name_qual == "CommunityData":
        # We called community data. Lets check our args
        if context.check_call_arg_value(
            "mpModel", 0
        ) or context.check_call_arg_value("mpModel", 1):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.HIGH,
                text="The use of SNMPv1 and SNMPv2 is insecure. "
                "You should use SNMPv3 if able.",
                lineno=context.get_lineno_for_call_arg("CommunityData"),
            )


@test.checks("Call")
@test.test_id("B509")
def snmp_crypto_check(context):
    """**B509: Checking for weak cryptography**

    This test is for checking for the usage of insecure SNMP cryptography:
      v3 using noAuthNoPriv.

    Using the pysnmp documentation:
      http://snmplabs.com/pysnmp/examples/hlapi/asyncore/sync/manager/cmdgen/snmp-versions.html

    Please update your code to use more secure versions of SNMP. For example:

    Instead of:
      `CommunityData('public', mpModel=0)`

    Use (Defaults to usmHMACMD5AuthProtocol and usmDESPrivProtocol
      `UsmUserData("securityName", "authName", "privName")`

    .. versionadded:: 1.7.2
    """

    if context.call_function_name_qual == "UsmUserData":
        if context.call_args_count < 3:
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.HIGH,
                text="You should not use SNMPv3 without encryption. "
                "noAuthNoPriv & authNoPriv is insecure",
                lineno=context.get_lineno_for_call_arg("UsmUserData"),
            )
