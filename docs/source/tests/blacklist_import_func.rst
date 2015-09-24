
blacklist_import_func
=====================
Description
-----------
This test is in all ways identical to :doc:`blacklist_imports`. However, it
is designed to catch modules that have been imported using Python's special
builtin import function, `__import__()`. For example, running a test on the
following code for `module.evil` would warn as shown:

.. code-block:: python

    __import__('module')                    # no warning
    __import__('module.evil')               # warning

Please see the documentation for :doc:`blacklist_imports` for more details.

Available Since
---------------
 - Bandit v0.9.0

Config Options
--------------
This test shares the configuration provided for the standard
:doc:`blacklist_imports` test.


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
- :doc:`blacklist_imports`.
- https://security.openstack.org
