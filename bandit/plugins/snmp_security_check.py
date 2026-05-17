#
# Copyright (c) 2018 SolarWinds, Inc.
#
# SPDX-License-Identifier: Apache-2.0
import bandit
from bandit.core import issue
from bandit.core import test_properties as test


_MISSING = object()
_UNKNOWN = object()


def _call_arg_value(context, name, position, default=_MISSING):
    keywords = context.call_keywords or {}
    if name in keywords:
        value = context.get_call_arg_value(name)
        return _UNKNOWN if value is None else value

    if context.call_args_count and context.call_args_count > position:
        value = context.get_call_arg_at_position(position)
        return _UNKNOWN if value is None else value

    return default


def _line_for_call(context, argument_name=None):
    if argument_name is not None:
        return (
            context.get_lineno_for_call_arg(argument_name)
            or context.node.lineno
        )
    return context.node.lineno


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
        mp_model = _call_arg_value(context, "mpModel", 1, default=1)
        if mp_model in (0, 1):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.HIGH,
                cwe=issue.Cwe.CLEARTEXT_TRANSMISSION,
                text="The use of SNMPv1 and SNMPv2 is insecure. "
                "You should use SNMPv3 if able.",
                lineno=_line_for_call(context, "mpModel"),
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
        priv_key = _call_arg_value(context, "privKey", 2)
        if priv_key in (_MISSING, "None"):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.HIGH,
                cwe=issue.Cwe.CLEARTEXT_TRANSMISSION,
                text="You should not use SNMPv3 without encryption. "
                "noAuthNoPriv & authNoPriv is insecure",
                lineno=_line_for_call(context, "privKey"),
            )
