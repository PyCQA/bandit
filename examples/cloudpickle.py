import cloudpickle
import io

# cloudpickle
pick = cloudpickle.dumps({'a': 'b', 'c': 'd'})
print(cloudpickle.loads(pick))

file_obj = io.BytesIO()
cloudpickle.dump([1, 2, '3'], file_obj)
file_obj.seek(0)
print(cloudpickle.load(file_obj))
