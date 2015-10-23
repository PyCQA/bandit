
start_process_with_a_shell
==============================================

Description
-----------
Python possesses many mechanisms to invoke an external executable. However,
doing so may present a security issue if appropriate care is not taken to
sanitize any user provided or variable input.

This plugin test is part of a family of tests built to check for process
spawning and warn appropriately. Specifically, this test looks for the spawning
of a subprocess using a command shell. This type of subprocess invocation is
dangerous as it is vulnerable to various shell injection attacks. Great care
should be taken to sanitize all input in order to mitigate this risk. Calls of
this type are identified by the use of certain commands which are known to use
shells. Bandit will report a MEDIUM severity warning.

See also:

- :doc:`linux_commands_wildcard_injection`.
- :doc:`subprocess_without_shell_equals_true`.
- :doc:`start_process_with_no_shell`.
- :doc:`start_process_with_partial_path`.
- :doc:`subprocess_popen_with_shell_equals_true`.

Available Since
---------------
 - Bandit v0.10.0

Config Options
--------------
This plugin test shares a configuration with others in the same family, namely
`shell_injection`. This configuration is divided up into three sections,
`subprocess`, `shell` and `no_shell`. They each list Python calls that spawn
subprocesses, invoke commands within a shell, or invoke commands without a
shell (by replacing the calling process) respectively.

This plugin specifically scans for methods listed in `shell` section.

.. code-block:: yaml

    shell_injection:
        shell:
            - os.system
            - os.popen
            - os.popen2
            - os.popen3
            - os.popen4
            - popen2.popen2
            - popen2.popen3
            - popen2.popen4
            - popen2.Popen3
            - popen2.Popen4
            - commands.getoutput
            - commands.getstatusoutput

Sample Output
-------------
.. code-block:: none

    >> Issue: Starting a process with a shell: check for injection.
       Severity: Medium   Confidence: Medium
       Location: examples/os_system.py:3
    2
    3   os.system('/bin/echo hi')

References
----------
- https://security.openstack.org
- https://docs.python.org/2/library/os.html#os.system
- https://docs.python.org/2/library/subprocess.html#frequently-used-arguments
- https://security.openstack.org/guidelines/dg_use-subprocess-securely.html
