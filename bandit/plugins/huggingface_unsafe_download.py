# Copyright (c) 2024 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
r"""
==================================================
B615: Test for unsafe Hugging Face Hub downloads
==================================================

This plugin checks for unsafe downloads from Hugging Face Hub without proper
integrity verification. Downloading models, datasets, or files without
specifying a revision (commit hash, tag, or branch) can lead to supply chain
attacks where malicious actors could replace model files.

The secure approach is to:

1. Pin to specific revisions/commits when downloading models or datasets
2. Use authentication tokens for private repositories
3. Verify file integrity when possible

Common unsafe patterns:
- ``AutoModel.from_pretrained("model-name")`` without revision
- ``load_dataset("dataset-name")`` without revision
- ``hf_hub_download()`` without revision parameter
- ``snapshot_download()`` without revision parameter

:Example:

.. code-block:: none

        >> Issue: Unsafe Hugging Face Hub download without revision pinning
        Severity: Medium   Confidence: High
        CWE: CWE-494 (https://cwe.mitre.org/data/definitions/494.html)
        Location: examples/huggingface_unsafe_download.py:8
        7    # Unsafe: no revision specified
        8    model = AutoModel.from_pretrained("bert-base-uncased")
        9

.. seealso::

     - https://cwe.mitre.org/data/definitions/494.html
     - https://huggingface.co/docs/hub/security-best-practices
     - https://huggingface.co/docs/huggingface_hub/guides/download

.. versionadded:: 1.9.0

"""
import bandit
from bandit.core import issue
from bandit.core import test_properties as test


@test.checks("Call")
@test.test_id("B615")
def huggingface_unsafe_download(context):
    """
    This plugin checks for unsafe downloads from Hugging Face Hub without
    proper revision pinning. This can lead to supply chain vulnerabilities.
    """
    # Check if any HuggingFace-related modules are imported
    hf_modules = [
        "transformers",
        "datasets",
        "huggingface_hub",
    ]

    # Check if any HF modules are imported
    hf_imported = any(
        context.is_module_imported_like(module) for module in hf_modules
    )

    if not hf_imported:
        return

    qualname = context.call_function_name_qual
    if not isinstance(qualname, str):
        return

    unsafe_patterns = {
        # transformers library patterns
        "from_pretrained": ["transformers"],
        # datasets library patterns
        "load_dataset": ["datasets"],
        # huggingface_hub patterns
        "hf_hub_download": ["huggingface_hub"],
        "snapshot_download": ["huggingface_hub"],
        "repository_id": ["huggingface_hub"],
    }

    qualname_parts = qualname.split(".")
    func_name = qualname_parts[-1]

    if func_name not in unsafe_patterns:
        return

    required_modules = unsafe_patterns[func_name]
    if not any(module in qualname_parts for module in required_modules):
        return

    # Check for revision parameter (the key security control)
    revision_specified = False

    # Some different various ways revision can be specified
    revision_params = ["revision", "commit_id", "use_auth_token"]
    for param in revision_params:
        if context.get_call_arg_value(param) is not None:
            revision_specified = True
            break

    # Found one!
    if revision_specified:
        return

    # Edge case: check if this is a local path (starts with ./ or /)
    first_arg = context.get_call_arg_at_position(0)
    if first_arg and isinstance(first_arg, str):
        if first_arg.startswith(("./", "/", "../")):
            # Local paths are generally safer
            return

    return bandit.Issue(
        severity=bandit.MEDIUM,
        confidence=bandit.HIGH,
        text=(
            f"Unsafe Hugging Face Hub download without revision pinning "
            f"in {func_name}()"
        ),
        cwe=issue.Cwe.IMPROPER_INPUT_VALIDATION,
        lineno=context.get_lineno_for_call_arg(func_name),
    )
