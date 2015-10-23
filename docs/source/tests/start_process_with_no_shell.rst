
start_process_with_no_shell
==============================================

Description
-----------
Python possesses many mechanisms to invoke an external executable. However,
doing so may present a security issue if appropriate care is not taken to
sanitize any user provided or variable input.

This plugin test is part of a family of tests built to check for process
spawning and warn appropriately. Specifically, this test looks for the spawning
of a subprocess in a way that doesn't use a shell. Although this is generally
safe, it maybe useful for penetration testing workflows to track where external
system calls are used.  As such a LOW severity message is generated.

See also:

- :doc:`linux_commands_wildcard_injection`.
- :doc:`subprocess_without_shell_equals_true`.
- :doc:`start_process_with_a_shell`.
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

This plugin specifically scans for methods listed in `no_shell` section.

.. code-block:: yaml

    shell_injection:
        no_shell:
            - os.execl
            - os.execle
            - os.execlp
            - os.execlpe
            - os.execv
            - os.execve
            - os.execvp
            - os.execvpe
            - os.spawnl
            - os.spawnle
            - os.spawnlp
            - os.spawnlpe
            - os.spawnv
            - os.spawnve
            - os.spawnvp
            - os.spawnvpe
            - os.startfile
Sample Output
-------------
.. code-block:: none

    >> Issue: [start_process_with_no_shell] Starting a process without a shell.
       Severity: Low   Confidence: Medium
       Location: examples/os-spawn.py:8
    7   os.spawnv(mode, path, args)
    8   os.spawnve(mode, path, args, env)
    9   os.spawnvp(mode, file, args)

References
----------
- https://security.openstack.org
- https://docs.python.org/2/library/os.html#os.system
- https://docs.python.org/2/library/subprocess.html#frequently-used-arguments
- https://security.openstack.org/guidelines/dg_use-subprocess-securely.html
