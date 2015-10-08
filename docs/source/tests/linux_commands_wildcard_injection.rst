
linux_commands_wildcard_injection
=================================

Description
-----------
Python provides a number of methods that emulate the behavior of standard Linux
command line utilities. Like their Linux counterparts, these commands may take
a wildcard "\*" character in place of a file system path. This is interpreted
to mean "any and all files or folders" and can be used to build partially
qualified paths, such as "/home/user/\*".

The use of partially qualified paths may result in unintended consequences if
an unexpected file or symlink is placed into the path location given. This
becomes particularly dangerous when combined with commands used to manipulate
file permissions or copy data off of a system.

This test plugin looks for usage of the following commands in conjunction with
wild card parameters:

- 'chown'
- 'chmod'
- 'tar'
- 'rsync'

As well as any method configured in the shell or subprocess injection test
configurations. See also :doc:`start_process_with_partial_path` for related
issues with partial paths.


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

This test will scan parameters of all methods in all sections. Note that methods
are fully qualified and de-aliased prior to checking.

see also:

- :doc:`start_process_with_partial_path`
- :doc:`start_process_with_a_shell`
- :doc:`start_process_with_no_shell`

.. code-block:: yaml

    shell_injection:
        # Start a process using the subprocess module, or one of its wrappers.
        subprocess:
            - subprocess.Popen
            - subprocess.call

        # Start a process with a function vulnerable to shell injection.
        shell:
            - os.system
            - os.popen
            - popen2.Popen3
            - popen2.Popen4
            - commands.getoutput
            - commands.getstatusoutput
        # Start a process with a function that is not vulnerable to shell injection.
        no_shell:
            - os.execl
            - os.execle


Sample Output
-------------
.. code-block:: none

    >> Issue: Possible wildcard injection in call: subprocess.Popen
       Severity: High   Confidence: Medium
       Location: ./examples/wildcard-injection.py:8
    7    o.popen2('/bin/chmod *')
    8    subp.Popen('/bin/chown *', shell=True)
    9

    >> Issue: subprocess call - check for execution of untrusted input.
       Severity: Low   Confidence: High
       Location: ./examples/wildcard-injection.py:11
    10   # Not vulnerable to wildcard injection
    11   subp.Popen('/bin/rsync *')
    12   subp.Popen("/bin/chmod *")


References
----------
- https://security.openstack.org
- https://en.wikipedia.org/wiki/Wildcard_character
- http://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt
