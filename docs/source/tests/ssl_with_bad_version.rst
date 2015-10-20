
ssl_with_bad_version
====================

Description
-----------
Several highly publicized [1]_ [2]_, exploitable flaws have been discovered in
all versions of SSL and early versions of TLS. It is strongly recommended that
use of the following known broken protocol versions be avoided:

- SSL v2
- SSL v3
- TLS v1
- TLS v1.1

This plugin test scans for calls to Python methods with parameters that indicate
the used broken SSL/TLS protocol versions. Currently, detection supports methods
using Python's native SSL/TLS support and the pyOpenSSL module. A HIGH severity
warning will be reported whenever known broken protocol versions are detected.

It is worth noting that native support for TLS 1.2 is only available in more
recent Python versions, specifically 2.7.9 and up, and 3.x

See also:

- :doc:`ssl_with_bad_defaults`.
- :doc:`ssl_with_no_version`.

A note on 'SSLv23'
------------------
Amongst the available SSL/TLS versions provided by Python/pyOpenSSL there exists
the option to use SSLv23. This very poorly named option actually means "use the
highest version of SSL/TLS supported by both the server and client". This may
(and should be) a version well in advance of SSL v2 or v3. Bandit can scan for
the use of SSLv23 if desired, but its detection does not necessarily indicate a
problem.

When using SSLv23 it is important to also provide flags to explicitly exclude
bad versions of SSL/TLS from the protocol versions considered. Both the Python
native and pyOpenSSL modules provide the ``OP_NO_SSLv2`` and ``OP_NO_SSLv3``
flags for this purpose.


Available Since
---------------
 - Bandit v0.9.0

 .. _bad_ssl_config_options:

Config Options
--------------
.. code-block:: yaml

    ssl_with_bad_version:
        bad_protocol_versions:
            - PROTOCOL_SSLv2
            - SSLv2_METHOD
            - SSLv23_METHOD
            - PROTOCOL_SSLv3  # strict option
            - PROTOCOL_TLSv1  # strict option
            - SSLv3_METHOD    # strict option
            - TLSv1_METHOD    # strict option


Sample Output
-------------
.. code-block:: none

    >> Issue: ssl.wrap_socket call with insecure SSL/TLS protocol version
    identified, security issue.
       Severity: High   Confidence: High
       Location: ./examples/ssl-insecure-version.py:13
    12  # strict tests
    13  ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv3)
    14  ssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1)

References
----------
- [1] http://heartbleed.com/
- [2] https://poodlebleed.com/
- https://security.openstack.org/
- https://security.openstack.org/guidelines/dg_move-data-securely.html

