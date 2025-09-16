# bandit/plugins/yaml_unsafe_loader.py
"""
B901: Detect usage of yaml.full_load, yaml.unsafe_load, or yaml.load with unsafe Loader.
Small Bandit plugin to explicitly flag full_load/unsafe_load and non-safe Loader usage.
"""

import bandit
from bandit.core import test_properties as test

# Register as a Call-check with a test id so Bandit will run it
@test.test_id("B901")
@test.checks("Call")
def yaml_unsafe_loader(context):
    """
    Flag:
      - yaml.full_load(...)
      - yaml.unsafe_load(...)
      - yaml.load(..., Loader=SomeLoader) if loader name does not indicate 'safe'
    """
    func_name = context.call_function_name_qual or ""

    # direct unsafe calls: yaml.full_load(), yaml.unsafe_load()
    if "yaml.full_load" in func_name or "yaml.unsafe_load" in func_name:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            text="Use of yaml.full_load()/yaml.unsafe_load() detected. Prefer yaml.safe_load() "
                 "when parsing untrusted YAML."
        )

    # yaml.load(...) with Loader=... where loader isn't safe
    if "yaml.load" in func_name:
        node = context.node  # AST Call node
        for kw in getattr(node, "keywords", []):
            if kw.arg == "Loader":
                val = kw.value
                loader_name = ""
                # e.g. Loader=yaml.FullLoader  -> val.attr == 'FullLoader'
                if hasattr(val, "attr"):
                    loader_name = val.attr
                # e.g. Loader=FullLoader  -> val.id == 'FullLoader'
                elif hasattr(val, "id"):
                    loader_name = val.id
                # Fallback: try string literal
                elif hasattr(val, "s"):
                    loader_name = getattr(val, "s", "")
                if loader_name:
                    # if loader name doesn't contain "safe", flag it
                    if "safe" not in loader_name.lower():
                        return bandit.Issue(
                            severity=bandit.MEDIUM,
                            confidence=bandit.MEDIUM,
                            text=f"yaml.load() used with Loader={loader_name!r} - this can be unsafe "
                                 "for untrusted input. Consider yaml.safe_load()."
                        )

    # no issue found
    return None
