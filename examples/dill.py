import dill
import io

# dill
pick = dill.dumps({'a': 'b', 'c': 'd'})
print(dill.loads(pick))

file_obj = io.BytesIO()
dill.dump([1, 2, '3'], file_obj)
file_obj.seek(0)
print(dill.load(file_obj))

file_obj.seek(0)
print(dill.Unpickler(file_obj).load())
