import importlib
a = importlib.import_module('os')
b = importlib.import_module('pickle')
c = importlib.__import__('sys')
d = importlib.__import__('subprocess')

# Do not crash when target is an expression
e = importlib.import_module(MODULE_MAP[key])
f = importlib.__import__(MODULE_MAP[key])

# Do not crash when target is a named argument
g = importlib.import_module(name='sys')
h = importlib.__import__(name='subprocess')
i = importlib.import_module(name='subprocess', package='bar.baz')
j = importlib.__import__(name='sys', package='bar.baz')
