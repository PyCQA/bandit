
subprocess_without_shell_equals_true
==============================================

Description
-----------
Python possesses many mechanisms to invoke an external executable. However,
doing so may present a security issue if appropriate care is not taken to
sanitize any user provided or variable input.

This plugin test is part of a family of tests built to check for process
spawning and warn appropriately. Specifically, this test looks for the spawning
of a subprocess without the use of a command shell. This type of subprocess
invocation is not vulnerable to shell injection attacks, but care should still
be taken to ensure validity of input.

Because this is a lesser issue than that described in
`subprocess_popen_with_shell_equals_true` a LOW severity warning is reported.

See also:

- :doc:`linux_commands_wildcard_injection`.
- :doc:`subprocess_popen_with_shell_equals_true`.
- :doc:`start_process_with_no_shell`.
- :doc:`start_process_with_a_shell`.
- :doc:`start_process_with_partial_path`.

Available Since
---------------
 - Bandit v0.9.0

Config Options
--------------
This plugin test shares a configuration with others in the same family, namely
`shell_injection`. This configuration is divided up into three sections,
`subprocess`, `shell` and `no_shell`. They each list Python calls that spawn
subprocesses, invoke commands within a shell, or invoke commands without a
shell (by replacing the calling process) respectively.

This plugin specifically scans for methods listed in `subprocess` section that
have shell=False specified.

.. code-block:: yaml

    shell_injection:
        # Start a process using the subprocess module, or one of its wrappers.
        subprocess:
            - subprocess.Popen
            - subprocess.call


Sample Output
-------------
.. code-block:: none

    >> Issue: subprocess call - check for execution of untrusted input.
       Severity: Low   Confidence: High
       Location: ./examples/subprocess_shell.py:23
    22
    23    subprocess.check_output(['/bin/ls', '-l'])
    24

References
----------
- https://security.openstack.org
- https://docs.python.org/2/library/subprocess.html#frequently-used-arguments
- https://security.openstack.org/guidelines/dg_avoid-shell-true.html
- https://security.openstack.org/guidelines/dg_use-subprocess-securely.html
