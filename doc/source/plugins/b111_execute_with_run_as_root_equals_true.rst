--------------------------------------------------
B111: Test for the use of rootwrap running as root
--------------------------------------------------

This plugin has been removed.

Running commands as root dramatically increase their potential risk. Running
commands with restricted user privileges provides defense in depth against
command injection attacks, or developer and configuration error. This plugin
test checks for specific methods being called with a keyword parameter
`run_as_root` set to True, a common OpenStack idiom.
