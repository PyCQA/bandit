Predictable temporary path
=====================
Creating a temporary file on disk is a common practice, however it has the
potential to be a source of problems. Naively creating such files using the
system wide ``/tmp`` folder for example, may result in predictable and
unprotected file paths. This could allow an attacker to anticipate where
temporary files will be found and to read or modify them. Manipulation of
temporary files can result in the ability to control, deny or damage a process
or system, or gain access to sensitive information. Please see [0] for more
details.

### Correct
```python
import tempfile
tmp = tempfile.mkstemp()
```

### Incorrect
```python
tmp = open('/tmp/my-tmp-file')
tmp = open(tempfile.mktemp(), "w")
```

## Consequences
* Unintended control of processes or systems
* Unintended destruction or denial of services
* Data theft or leakage

## References
* [0] https://security.openstack.org/guidelines/dg_using-temporary-files-securely.html
