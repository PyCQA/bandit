
set_bad_file_permissions
========================

Description
-----------
POSIX based operating systems utilize a permissions model to protect access to
parts of the file system. This model supports three roles "owner", "group"
and "world" each role may have a combination of "read", "write" or "execute"
flags sets. Python provides ``chmod`` to manipulate POSIX style permissions.

This plugin test looks for the use of ``chmod`` and will alert when it is used
to set particularly permissive control flags. A MEDIUM warning is generated if
a file is set to group executable and a HIGH warning is reported if a file is
set world writable. Warnings are given with HIGH confidence.

Available Since
---------------
 - Bandit v0.9.0

Config Options
--------------
None

Sample Output
-------------
.. code-block:: none

    >> Issue: Probable insecure usage of temp file/directory.
       Severity: Medium   Confidence: Medium
       Location: ./examples/os-chmod-py2.py:15
    14  os.chmod('/etc/hosts', 0o777)
    15  os.chmod('/tmp/oh_hai', 0x1ff)
    16  os.chmod('/etc/passwd', stat.S_IRWXU)

    >> Issue: Chmod setting a permissive mask 0777 on file (key_file).
       Severity: High   Confidence: High
       Location: ./examples/os-chmod-py2.py:17
    16  os.chmod('/etc/passwd', stat.S_IRWXU)
    17  os.chmod(key_file, 0o777)
    18

References
----------
- https://security.openstack.org/guidelines/dg_apply-restrictive-file-permissions.html
- https://en.wikipedia.org/wiki/File_system_permissions
- https://security.openstack.org
