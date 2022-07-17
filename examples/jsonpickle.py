import jsonpickle


pick = jsonpickle.encode({'a': 'b', 'c': 'd'})

print(jsonpickle.decode(pick))

print(jsonpickle.unpickler.decode(pick))

print(jsonpickle.unpickler.Unpickler().restore(pick))
