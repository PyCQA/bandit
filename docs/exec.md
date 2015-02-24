exec()
=====================
The [python docs](https://docs.python.org/2.0/ref/exec.html) succinctly describe why ```exec()``` is bad:
* "This statement supports dynamic execution of Python code."

### Correct
Look for alternate solutions than ```exec```; often times you can find other modules or builtins to complete the task securely.

If ```exec``` is absolutely necessary, extreme care must be taken to ensure no untrusted input is included in the expression that ```exec``` evaluates.

### Incorrect
A common use case is to to read a file and then exec the content to execute Python within your currently running script, e.g:
```python
exec( open('setup.py','rb').read() )
```

That is obviously scary because you are executing the Python code in setup.py.  Another example that is even more scary is a practice similar to:
```python
exec 'from ' + mod_name + ' import test'
```

If we set mod_name to ```unittest```, everything works normally. However, if we set mod_name to ```unittest import test; import ast #``` we've successfully imported a module that the developer did not intend.

## Consequences
* Unintended code execution

## References
* [0] https://docs.python.org/2.0/ref/exec.html
