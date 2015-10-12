
paramiko_calls
==============

Description
-----------
Paramiko is a Python library designed to work with the SSH2 protocol for secure
(encrypted and authenticated) connections to remote machines. It is intended to
run commands on a remote host. These commands are run within a shell on the
target and are thus vulnerable to various shell injection attacks. Bandit
reports a MEDIUM issue when it detects the use of Paramiko's "exec_command" or
"invoke_shell" methods advising the user to check inputs are correctly
sanitized.

See also:

- :doc:`start_process_with_a_shell`
- :doc:`subprocess_popen_with_shell_equals_true`


Available Since
---------------
 - Bandit v0.12.0

Config Options
--------------
None

Sample Output
-------------
.. code-block:: none

    >> Issue: Possible shell injection via Paramiko call, check inputs are properly sanitized.
       Severity: Medium   Confidence: Medium
       Location: ./examples/paramiko_injection.py:4
    3    # this is not safe
    4    paramiko.exec_command('something; reallly; unsafe')
    5

    >> Issue: Possible shell injection via Paramiko call, check inputs are properly sanitized.
       Severity: Medium   Confidence: Medium
       Location: ./examples/paramiko_injection.py:10
    9    # this is not safe
    10   SSHClient.invoke_shell('something; bad; here\n')
    11

References
----------

- https://security.openstack.org
- https://github.com/paramiko/paramiko
- https://www.owasp.org/index.php/Command_Injection
