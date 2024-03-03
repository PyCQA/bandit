# Copyright (c) 2024 Stacklok, Inc.
#
# SPDX-License-Identifier: Apache-2.0
r"""
=========================================
B704: Test for unsafe PyTorch load or save
=========================================

This plugin checks for the use of `torch.load` and `torch.save`. Using `torch.load`
with untrusted data can lead to arbitrary code execution, and improper use of
`torch.save` might expose sensitive data or lead to data corruption.

:Example:

.. code-block:: none

        >> Issue: Use of unsafe PyTorch load or save
        Severity: Medium   Confidence: High
        CWE: CWE-94 (https://cwe.mitre.org/data/definitions/94.html)
        Location: examples/pytorch_load_save.py:8
        7    loaded_model.load_state_dict(torch.load('model_weights.pth'))
        8    another_model.load_state_dict(torch.load('model_weights.pth', map_location='cpu'))
        9
        10   print("Model loaded successfully!")

.. seealso::

     - https://cwe.mitre.org/data/definitions/94.html

.. versionadded:: 1.7.8

"""
import bandit
from bandit.core import issue
from bandit.core import test_properties as test


@test.checks("Call")
@test.test_id(
    "B704"
)  # Ensure the test ID is unique and does not conflict with existing Bandit tests
def pytorch_load_save(context):
    """
    This plugin checks for the use of `torch.load` and `torch.save`. Using `torch.load`
    with untrusted data can lead to arbitrary code execution, and improper use of
    `torch.save` might expose sensitive data or lead to data corruption.
    """
    imported = context.is_module_imported_exact("torch")
    qualname = context.call_function_name_qual
    if not imported and isinstance(qualname, str):
        return

    qualname_list = qualname.split(".")
    func = qualname_list[-1]
    if all(
        [
            "torch" in qualname_list,
            func in ["load"],
            not context.check_call_arg_value("map_location", "cpu"),
        ]
    ):
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            text="Use of unsafe PyTorch load or save",
            cwe=issue.Cwe.UNTRUSTED_INPUT,
            lineno=context.get_lineno_for_call_arg("load"),
        )
