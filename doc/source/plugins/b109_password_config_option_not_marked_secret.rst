---------------------------------------------------------------
B109: Test for a password based config option not marked secret
---------------------------------------------------------------

This plugin has been removed.

Passwords are sensitive and must be protected appropriately. In OpenStack
Oslo there is an option to mark options "secret" which will ensure that they
are not logged. This plugin detects usages of oslo configuration functions
that appear to deal with strings ending in 'password' and flag usages where
they have not been marked secret.

If such a value is found a MEDIUM severity error is generated. If 'False' or
'None' are explicitly set, Bandit will return a MEDIUM confidence issue. If
Bandit can't determine the value of secret it will return a LOW confidence
issue.
