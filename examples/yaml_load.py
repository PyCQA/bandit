import yaml

def test_yaml_load():
    ystr = yaml.dump({'a' : 1, 'b' : 2, 'c' : 3})
    y = yaml.load(ystr)
    yaml.dump(y)

