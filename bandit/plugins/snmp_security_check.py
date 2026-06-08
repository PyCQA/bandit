#
# Copyright (c) 2018 SolarWinds, Inc.
#
# SPDX-License-Identifier: Apache-2.0
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test


def _get_call_argument(context, name, position):
    keywords = context.call_keywords or {}
    if name in keywords:
        node = next(
            keyword.value
            for keyword in context.node.keywords
            if keyword.arg == name
        )
        return True, keywords[name], node
    if context.call_args_count and context.call_args_count > position:
        return (
            True,
            context.get_call_arg_at_position(position),
            context.node.args[position],
        )
    return False, None, None


def _is_none_literal(node):
    return isinstance(node, ast.Constant) and node.value is None


@test.checks("Call")
@test.test_id("B508")
def snmp_insecure_version_check(context):
    """**B508: Checking for insecure SNMP versions**

    This test is for checking for the usage of insecure SNMP version like
      v1, v2c

    Please update your code to use more secure versions of SNMP.

    :Example:

    .. code-block:: none

        >> Issue: [B508:snmp_insecure_version_check] The use of SNMPv1 and
           SNMPv2 is insecure. You should use SNMPv3 if able.
           Severity: Medium Confidence: High
           CWE: CWE-319 (https://cwe.mitre.org/data/definitions/319.html)
           Location: examples/snmp.py:4:4
           More Info: https://bandit.readthedocs.io/en/latest/plugins/b508_snmp_insecure_version_check.html
        3   # SHOULD FAIL
        4   a = CommunityData('public', mpModel=0)
        5   # SHOULD FAIL

    .. seealso::

     - http://snmplabs.com/pysnmp/examples/hlapi/asyncore/sync/manager/cmdgen/snmp-versions.html
     - https://cwe.mitre.org/data/definitions/319.html

    .. versionadded:: 1.7.2

    .. versionchanged:: 1.7.3
        CWE information added

    """  # noqa: E501

    if context.call_function_name_qual == "pysnmp.hlapi.CommunityData":
        provided, mp_model, node = _get_call_argument(context, "mpModel", 2)
        if not provided or _is_none_literal(node):
            mp_model = 1
        if mp_model in (0, 1):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.HIGH,
                cwe=issue.Cwe.CLEARTEXT_TRANSMISSION,
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

    Please update your code to use more secure versions of SNMP. For example:

    Instead of:
      `CommunityData('public', mpModel=0)`

    Use (Defaults to usmHMACMD5AuthProtocol and usmDESPrivProtocol
      `UsmUserData("securityName", "authName", "privName")`

    :Example:

    .. code-block:: none

        >> Issue: [B509:snmp_crypto_check] You should not use SNMPv3 without encryption. noAuthNoPriv & authNoPriv is insecure
           Severity: Medium CWE: CWE-319 (https://cwe.mitre.org/data/definitions/319.html) Confidence: High
           Location: examples/snmp.py:6:11
           More Info: https://bandit.readthedocs.io/en/latest/plugins/b509_snmp_crypto_check.html
        5   # SHOULD FAIL
        6   insecure = UsmUserData("securityName")
        7   # SHOULD FAIL

    .. seealso::

     - http://snmplabs.com/pysnmp/examples/hlapi/asyncore/sync/manager/cmdgen/snmp-versions.html
     - https://cwe.mitre.org/data/definitions/319.html

    .. versionadded:: 1.7.2

    .. versionchanged:: 1.7.3
        CWE information added

    """  # noqa: E501

    if context.call_function_name_qual == "pysnmp.hlapi.UsmUserData":
        provided, _, node = _get_call_argument(context, "privKey", 2)
        if not provided or _is_none_literal(node):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.HIGH,
                cwe=issue.Cwe.CLEARTEXT_TRANSMISSION,
                text="You should not use SNMPv3 without encryption. "
                "noAuthNoPriv & authNoPriv is insecure",
                lineno=context.get_lineno_for_call_arg("UsmUserData"),
            )
