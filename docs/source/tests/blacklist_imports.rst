
blacklist_imports
=================

Description
-----------
A number of Python modules are known to provide collections of functionality
with potential security implications. The blacklist imports plugin test is
designed to detect the use of these modules by scanning code for `import`
statements and checking for the imported modules presence in a configurable
blacklist. The imported modules are fully qualified and de-aliased prior to
checking. To illustrate this, imagine a check for "module.evil" running on the
following example code:

.. code-block:: python

    import module                    # no warning
    import module.evil               # warning
    from module import evil          # warning
    from module import evil as good  # warning

This would generate a warning about importing `module.evil` in each of the last
three cases, despite the module being aliased as `good` in one of them. It would
also not generate a warning on the first import (of `module`) as it's fully
qualified name will not match.

Each of the provided blacklisted modules can be grouped such that they generate
appropriate warnings (message, severity) and a token `{module}` may be used
in the provided output message, to be replaced with the actual module name.

Due to the nature of the test, confidence is always reported as HIGH

Available Since
---------------
 - Bandit v0.9.0

Config Options
--------------
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
                    Using {module} to parse untrusted XML data is known to be
                    vulnerable to XML attacks. Replace {module} with the
                    equivalent defusedxml package.
                level: LOW


Sample Output
-------------
.. code-block:: none

    >> Issue: Using xml.sax to parse untrusted XML data is known to be
    vulnerable to XML attacks. Replace xml.sax with the equivalent defusedxml
    package.

       Severity: Low   Confidence: High
       Location: ./examples/xml_sax.py:1
    1 import xml.sax
    2 from xml import sax

    >> Issue: Using xml.sax.parseString to parse untrusted XML data is known to
    be vulnerable to XML attacks. Replace xml.sax.parseString with its
    defusedxml equivalent function.

       Severity: Medium   Confidence: High
       Location: ./examples/xml_sax.py:21
    20  # bad
    21  xml.sax.parseString(xmlString, ExampleContentHandler())
    22  xml.sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler())

References
----------
- see also :doc:`blacklist_import_func`.
- https://security.openstack.org
