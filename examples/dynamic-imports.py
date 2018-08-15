import importlib

def get_dynamic_module(key):
    MODULE_MAP = {'db': 'sqlite3', 'data': 'json'}
    return importlib.import_module(MODULE_MAP[key])
