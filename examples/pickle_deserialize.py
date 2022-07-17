import io
import pickle


# pickle
pick = pickle.dumps({'a': 'b', 'c': 'd'})
print(pickle.loads(pick))

file_obj = io.BytesIO()
pickle.dump([1, 2, '3'], file_obj)
file_obj.seek(0)
print(pickle.load(file_obj))

file_obj.seek(0)
print(pickle.Unpickler(file_obj).load())
