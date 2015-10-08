any_other_function_with_shell_equals_true
=========================================

Description
-----------
Python possesses many mechanisms to invoke an external executable. However,
doing so may present a security issue if appropriate care is not taken to
sanitize any user provided or variable input.

This plugin test is part of a family of tests built to check for process
spawning and warn appropriately. Specifically, this plugin test interrogates
method calls for the presence of a keyword parameter `shell` equalling true. It
is related to detection of shell injection issues and is intended to catch
custom wrappers to vulnerable methods that may have been created.

See also:

- :doc:`linux_commands_wildcard_injection`.
- :doc:`subprocess_popen_with_shell_equals_true`.
- :doc:`subprocess_without_shell_equals_true`.
- :doc:`start_process_with_no_shell`.
- :doc:`start_process_with_a_shell`.
- :doc:`start_process_with_partial_path`.

Available Since
---------------
 - Bandit v 0.9.0

Config Options
--------------
This plugin test shares a configuration with others in the same family, namely
`shell_injection`. This configuration is divided up into three sections,
`subprocess`, `shell` and `no_shell`. They each list Python calls that spawn
subprocesses, invoke commands within a shell, or invoke commands without a
shell (by replacing the calling process) respectively.

Specifically, this plugin excludes those functions listed under the subprocess
section, these methods are tested in a separate specific test plugin and this
exclusion prevents duplicate issue reporting.

.. code-block:: yaml

    shell_injection:
        # Start a process using the subprocess module, or one of its wrappers.
        subprocess: [subprocess.Popen, subprocess.call, subprocess.check_call,
                     subprocess.check_output, utils.execute,
                     utils.execute_with_timeout]


Sample Output
-------------
.. code-block:: none

    >> Issue: Function call with shell=True parameter identified, possible
    security issue.
       Severity: Medium   Confidence: High
       Location: ./examples/subprocess_shell.py:9
    8 pop('/bin/gcc --version', shell=True)
    9 Popen('/bin/gcc --version', shell=True)
    10

References
----------
 - https://security.openstack.org/guidelines/dg_avoid-shell-true.html
 - https://security.openstack.org/guidelines/dg_use-subprocess-securely.html
