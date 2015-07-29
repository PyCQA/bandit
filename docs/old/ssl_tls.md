Avoid known weak or compromised SSL/TLS versions
=====================
Several well publicized vulnerabilities[0][1] have emerged in versions of
SSL/TLS. It is strongly recommended that software utilizing SSL/TLS for secure
transmissions should avoid the use of these known bad protocol versions.
Developers and deployers wishing to know more should refer to [2].

* Avoid the use of all versions of SSL (versions 2, 3 and before)
* Avoid the use of TLS versions 1.0, 1.1

### Correct
Good versions of TLS are defined in Python's built in ssl module as:
- 'PROTOCOL_SSLv23' only in conjunction with 'OP_NO_SSLv2' and 'OP_NO_SSLv3'
- 'PROTOCOL_TLSv1_2'

It is worth noting that TLS 1.2 is only available in more recent Python
versions, specifically 2.7.9, 2.7.10, and 3.x

Good versions of TLS are defined in the pyOpenSSL package as:
- 'SSLv23_METHOD' only in conjunction with 'OP_NO_SSLv2' and 'OP_NO_SSLv3'
- 'TLSv1_2_METHOD'

### Incorrect
Bad versions of SSL/TLS are defined in Python's built in ssl module as:
- 'PROTOCOL_SSLv2'
- 'PROTOCOL_SSLv3'
- 'PROTOCOL_TLSv1'
- 'PROTOCOL_TLSv1_1'

Bad versions of SSL/TLS are defined in the pyOpenSSL package as:
- 'SSLv2_METHOD'
- 'SSLv3_METHOD'
- 'TLSv1_METHOD'
- 'TLSv1_1_METHOD'

## Consequences
The following consequences may arise from the use of bad SSL/TLS protocol
versions:

* Unintended data leakage or theft
* System identity theft/impersonation (certificate theft)
* Burden caused by mass revocation of compromised certificates

## References
* [0] http://heartbleed.com/
* [1] http://googleonlinesecurity.blogspot.co.uk/2014/10/this-poodle-bites-exploiting-ssl-30.html
* [2] https://security.openstack.org/guidelines/dg_strong-crypto.html
