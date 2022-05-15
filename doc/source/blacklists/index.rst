Blacklist Plugins
=================

Bandit supports built in functionality to implement blacklisting of imports and
function calls, this functionality is provided by built in test 'B001'. This
test may be filtered as per normal plugin filtering rules.

The exact calls and imports that are blacklisted, and the issues reported, are
controlled by plugin methods with the entry point 'bandit.blacklists' and can
be extended by third party plugins if desired. Blacklist plugins will be
discovered by Bandit at startup and called. The returned results are combined
into the final data set, subject to Bandit's normal test include/exclude rules
allowing for fine grained control over blacklisted items. By convention,
blacklisted calls should have IDs in the B3xx range and imports should have IDs
in the B4xx range.

Plugin functions should return a dictionary mapping AST node types to
lists of blacklist data. Currently the following node types are supported:

- Call, used for blacklisting calls.
- Import, used for blacklisting module imports (this also implicitly tests
  ImportFrom and Call nodes where the invoked function is Pythons built in
  '__import__()' method).

Items in the data lists are Python dictionaries with the following structure:

+-------------+----------------------------------------------------+
| key         | data meaning                                       |
+=============+====================================================+
| 'name'      | The issue name string.                             |
+-------------+----------------------------------------------------+
| 'id'        | The bandit ID of the check, this must be unique    |
|             | and is used for filtering blacklist checks.        |
+-------------+----------------------------------------------------+
| 'qualnames' | A Python list of fully qualified name strings.     |
+-------------+----------------------------------------------------+
| 'message'   | The issue message reported, this is a string that  |
|             | may contain the token '{name}' that will be        |
|             | substituted with the matched qualname in the final |
|             | report.                                            |
+-------------+----------------------------------------------------+
| 'level'     | The severity level reported.                       |
+-------------+----------------------------------------------------+

A utility method bandit.blacklists.utils.build_conf_dict is provided to aid
building these dictionaries.

:Example:

.. code-block:: none

    >> Issue: [B317:blacklist] Using xml.sax.parse to parse untrusted XML data
    is known to be vulnerable to XML attacks. Replace xml.sax.parse with its
    defusedxml equivalent function.
        Severity: Medium   Confidence: High
        Location: ./examples/xml_sax.py:24
        23    sax.parseString(xmlString, ExampleContentHandler())
        24    sax.parse('notaxmlfilethatexists.xml', ExampleContentHandler)
        25

Complete Plugin Listing
-----------------------

.. toctree::
   :maxdepth: 1
   :glob:

   *

.. versionadded:: 0.17.0
