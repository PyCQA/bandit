import pickle

pick = pickle.dumps({'a': 'b', 'c': 'd'})
raw = pickle.loads(pick)
