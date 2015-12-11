Avoid spawning subprocess with partial paths
=====================
When launching a subprocess from within Python, care should be taken over
executable paths. The search path, normally the 'PATH' environment variable,
will be used to discover a executable binary if a fully qualified path is not
given. This can allow an attacker to manipulate the search path, or place a
similarly named executable at an early point, such that it will be executed in
preference to the expected executable.

Paths should be given either fully qualified from the filesystem root, or
relative to the running processes working directory. If it is desirable to use
unqualified executable names for the perpose of location independent deployments
then consider using paths relative to the deployment directory or deducing the
paths using mechanisms such as `os.cwd()`

### Correct
Fully qualified paths, or relative paths:
```python

os.Popen('/bin/ls -l', shell=False)
os.Popen(['/bin/ls', '-l'], shell=False)
os.Popen(['../ls', '-l'], shell=False)

```

### Incorrect
Unqualified executable names:
```python

os.Popen('ls -l', shell=False)
os.Popen(['ls', '-l'], shell=False)

```

## Consequences
The following consequences may arise from the use of unqualified paths

* Unintended execution of malicious binaries

## References
* https://cwe.mitre.org/data/definitions/426.html
