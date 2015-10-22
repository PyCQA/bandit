
ssl_with_no_version
===================

Description
-----------
Several highly publicized [1]_ [2]_, exploitable flaws have been discovered in
all versions of SSL and early versions of TLS. It is strongly recommended that
use of the following known broken protocol versions be avoided:

- SSL v2
- SSL v3
- TLS v1
- TLS v1.1

This plugin is part of a family of tests that detect the use of known bad
versions of SSL/TLS, please see :doc:`ssl_with_bad_version` for a complete
discussion. Specifically, This plugin test scans for specific methods in
Python's native SSL/TLS support and the pyOpenSSL module that configure the
version of SSL/TLS protocol to use. These methods are known to provide default
value that maximize compatibility, but permit use of the aforementioned broken
protocol versions. A LOW severity warning will be reported whenever this is
detected.

See also:

- :doc:`ssl_with_bad_version`.
- :doc:`ssl_with_bad_defaults`.


Available Since
---------------
 - Bandit v0.9.0

Config Options
--------------
This test shares the configuration provided for the standard
:doc:`ssl_with_bad_version` test, please refer to it's
:ref:`bad_ssl_config_options` documentation.

Sample Output
-------------
.. code-block:: none

    >> Issue: ssl.wrap_socket call with no SSL/TLS protocol version specified,
    the default SSLv23 could be insecure, possible security issue.
       Severity: Low   Confidence: Medium
       Location: ./examples/ssl-insecure-version.py:23
    22
    23  ssl.wrap_socket()
    24

References
----------
- [1] http://heartbleed.com/
- [2] https://poodlebleed.com/
- https://security.openstack.org/
- https://security.openstack.org/guidelines/dg_move-data-securely.html

