# -*- coding:utf-8 -*-
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
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
from bandit.core.test_properties import *


@takes_config
@checks('Import', 'ImportFrom')
def blacklist_imports(context, config):
    """blacklist_imports

    A number of Python modules are known to provide collections of
    functionality with potential security implications. The blacklist imports
    plugin test is designed to detect the use of these modules by scanning code
    for `import` statements and checking for the imported modules presence in a
    configurable blacklist. The imported modules are fully qualified and
    de-aliased prior to checking. To illustrate this, imagine a check for
    "module.evil" running on the following example code:

    .. code-block:: python

        import module                    # no warning
        import module.evil               # warning
        from module import evil          # warning
        from module import evil as good  # warning

    This would generate a warning about importing `module.evil` in each of the
    last three cases, despite the module being aliased as `good` in one of
    them. It would also not generate a warning on the first import
    (of `module`) as it's fully qualified name will not match.

    Each of the provided blacklisted modules can be grouped such that they
    generate appropriate warnings (message, severity) and a token `{module}`
    may be used in the provided output message, to be replaced with the actual
    module name.

    Due to the nature of the test, confidence is always reported as HIGH

    Config Options:

    .. code-block:: yaml

        blacklist_imports:
            bad_import_sets:
                - xml_libs:
                    imports:
                        - xml.etree.cElementTree
                        - xml.etree.ElementTree
                        - xml.sax.expatreader
                        - xml.sax
                        - xml.dom.expatbuilder
                        - xml.dom.minidom
                        - xml.dom.pulldom
                        - lxml.etree
                        - lxml
                    message: >
                        Using {module} to parse untrusted XML data is known to
                        be vulnerable to XML attacks. Replace {module} with the
                        equivalent defusedxml package.
                    level: LOW


    Sample Output:

    .. code-block:: none

        >> Issue: Using xml.sax to parse untrusted XML data is known to be
        vulnerable to XML attacks. Replace xml.sax with the equivalent
        defusedxml package.

           Severity: Low   Confidence: High
           Location: ./examples/xml_sax.py:1
        1 import xml.sax
        2 from xml import sax

        >> Issue: Using xml.sax.parseString to parse untrusted XML data is
        known to be vulnerable to XML attacks. Replace xml.sax.parseString with
        its defusedxml equivalent function.

           Severity: Medium   Confidence: High
           Location: ./examples/xml_sax.py:21
        20  # bad
        21  xml.sax.parseString(xmlString, ExampleContentHandler())
        22  xml.sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler())

    References:

    - https://security.openstack.org

    .. versionadded:: 0.9.0
    """

    checks = _load_checks(config)

    # for each check, go through and see if it matches all qualifications
    for check in checks:
        # item 0=import, 1=message, 2=level
        if check[0]:
            for im in check[0]:
                if context.is_module_being_imported(im):
                    return _get_result(check, im)


@takes_config('blacklist_imports')
@checks('Call')
def blacklist_import_func(context, config):
    """blacklist_import_func

    This test is in all ways identical blacklist_imports. However, it
    is designed to catch modules that have been imported using Python's special
    builtin import function, `__import__()`. For example, running a test on the
    following code for `module.evil` would warn as shown:

    .. code-block:: python

        __import__('module')                    # no warning
        __import__('module.evil')               # warning

    This test shares the configuration provided for the standard
    blacklist_imports test.


    Sample Output:

    .. code-block:: none

        >> Issue: Using xml.sax to parse untrusted XML data is known to be
        vulnerable to XML attacks. Replace xml.sax with the equivalent
        defusedxml package.

           Severity: Low   Confidence: High
           Location: ./examples/xml_sax.py:1
        1 import xml.sax
        2 from xml import sax

        >> Issue: Using xml.sax.parseString to parse untrusted XML data is
        known to be vulnerable to XML attacks. Replace xml.sax.parseString with
        its defusedxml equivalent function.

           Severity: Medium   Confidence: High
           Location: ./examples/xml_sax.py:21
        20  # bad
        21  xml.sax.parseString(xmlString, ExampleContentHandler())
        22  xml.sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler())


    References:

    - https://security.openstack.org

    .. versionadded:: 0.9.0
    """
    checks = _load_checks(config)
    if context.call_function_name_qual == '__import__':
        for check in checks:
            # item 0=import, 1=message, 2=level
            if check[0]:
                for im in check[0]:
                    if len(context.call_args) and im == context.call_args[0]:
                        return _get_result(check, im)


def _load_checks(config):
    # load all the checks from the config file
    if config is not None and 'bad_import_sets' in config:
        sets = config['bad_import_sets']
    else:
        sets = []

    checks = []
    for cur_item in sets:
        for blacklist_item in cur_item:
            blacklist_object = cur_item[blacklist_item]
            cur_check = _get_tuple_for_item(blacklist_object)
            # skip bogus checks
            if cur_check:
                checks.append(cur_check)
    return checks


def _get_tuple_for_item(blacklist_object):
    # default values
    imports = None
    message = ""
    level = 'MEDIUM'

    # if the item we got passed isn't a dictionary, do nothing with the object;
    # if the item we got passed doesn't have an imports field, we can't do
    # anything with this.  Return None
    if (not isinstance(blacklist_object, dict) or
            'imports' not in blacklist_object):
        return None

    imports = blacklist_object['imports']

    if 'message' in blacklist_object:
        message = blacklist_object['message']

    if 'level' in blacklist_object:
        if blacklist_object['level'] == 'HIGH':
            level = 'HIGH'
        elif blacklist_object['level'] == 'MEDIUM':
            level = 'MEDIUM'
        elif blacklist_object['level'] == 'LOW':
            level = 'LOW'

    return_tuple = (imports, message, level)
    return return_tuple


def _get_result(check, im):
    # substitute '{module}' for the imported module name
    message = check[1].replace('{module}', im)

    level = None
    if check[2] == 'HIGH':
        level = bandit.HIGH
    elif check[2] == 'MEDIUM':
        level = bandit.MEDIUM
    elif check[2] == 'LOW':
        level = bandit.LOW

    return bandit.Issue(severity=level, confidence=bandit.HIGH, text=message)
