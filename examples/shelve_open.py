import os
import shelve
import tempfile

with tempfile.TemporaryDirectory() as d:
    filename = os.path.join(d, 'shelf')

    with shelve.open(filename) as db:
        db['spam'] = {'eggs': 'ham'}

    with shelve.open(filename) as db:
        print(db['spam'])
