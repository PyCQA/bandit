
hardcoded_tmp_directory
=======================

Description
-----------
Safely creating a temporary file or directory means following a number of rules
(see the references for more details). This plugin test looks for strings
starting with (configurable) commonly used temporary paths, for example:

 - /tmp
 - /var/tmp
 - /dev/shm
 - etc

Available Since
---------------
 - Bandit v0.9.0

Config Options
--------------
This test plugin takes a similarly named config block, `hardcoded_tmp_directory`.
The config block provides a Python list, `tmp_dirs`, that lists string fragments
indicating possible temporary file paths. Any string starting with one of these
fragments will report a MEDIUM confidence issue.

.. code-block:: yaml

    hardcoded_tmp_directory:
        tmp_dirs:  ['/tmp', '/var/tmp', '/dev/shm']


Sample Output
-------------
.. code-block: none

    >> Issue: Probable insecure usage of temp file/directory.
       Severity: Medium   Confidence: Medium
       Location: ./examples/hardcoded-tmp.py:1
    1 f = open('/tmp/abc', 'w')
    2 f.write('def')

References
----------
 - https://security.openstack.org/guidelines/dg_using-temporary-files-securely.html
