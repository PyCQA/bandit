import importlib
a = importlib.import_module('os')
b = importlib.import_module('pickle')
c = importlib.__import__('sys')
d = importlib.__import__('subprocess')

# Do not crash when target is an expression
e = importlib.import_module(MODULE_MAP[key])
f = importlib.__import__(MODULE_MAP[key])
