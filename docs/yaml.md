yaml.load()
=====================
The [PyYaml docs](http://pyyaml.org/wiki/PyYAMLDocumentation#LoadingYAML) have
details on why using ```yaml.load()``` with untrusted user data is very scary.

```yaml.load()``` can lead to remote code execution - ```yaml.safe_load()```
should be used whenever parsing untrusted YAML.


### Incorrect
We'll use [Paul McMillan's
gist](https://gist.github.com/PaulMcMillan/c4d560471dd529fdf9f3) to demonstrate
why ```yaml.load()``` is scary. We start by defining a few things for our
exploit, starting with ```exploit.py``` will look like:
```python
print 'WINNA WINNA'
```

In order to get ```yaml.load()``` to properly execute our Python, we have to do
some careful encoding.
```python
encoded = ("eval(compile('%s'.decode('base64'), '<string>', 'exec'))" % exploit.encode('base64').replace('\n', ''))
```

After executing the above, our ```encoded``` variable looks like:
```"eval(compile('cHJpbnQgIldJTk5BIFdJTk5BIgo='.decode('base64'), '<string>', 'exec'))"```

Next, we build the actual YAML object:
```python
yaml_object = ('\nupgrade_helper: !!python/object/apply:eval ["%s",]\n' % encoded)
```

This results in ```yaml_object``` looking like:
```
'\nupgrade_helper: !!python/object/apply:eval ["eval(compile(\'cHJpbnQgIldJTk5BIFdJTk5BIgo=\'.decode(\'base64\'), \'<string>\', \'exec\'))",]\n'
```

We then take that ```yaml_object``` and print it to a file ```exploit.yaml```, it will look like:
```
upgrade_helper: !!python/object/apply:eval ["eval(compile('cHJpbnQgIldJTk5BIFdJTk5BIgo='.decode('base64'), '<string>', 'exec'))",]
```

Ok, all the setup is done. All we need to do now is
```yaml.load(open("exploit.yaml").read())```. We can see from the output that
our ```print``` was executed and ```WINNA WINNA``` was printed to STDOUT:
```console
>>> yaml.load(open("exploit.yaml"))
    WINNA WINNA
```

### Correct
Use ```yaml.safe_load()``` instead of ```yaml.load()```. In the PoC above, if we
try to load ```exploit.yaml``` via ```safe_load()``` we get the following error:
```
>>> yaml.safe_load(open("exploit.yaml"))
Traceback (most recent call last):
...
yaml.constructor.ConstructorError: could not determine a constructor for the tag 'tag:yaml.org,2002:python/object/apply:eval'
  in "exploit.yaml", line 1, column 17
```

## Consequences
* Remote code execution

## References
* http://pyyaml.org/wiki/PyYAMLDocumentation#LoadingYAML
* https://gist.github.com/PaulMcMillan/c4d560471dd529fdf9f3
