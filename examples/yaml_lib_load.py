from ruamel.yaml import YAML


def not_a_vul(content):
    yaml = YAML(typ='safe')
    c = yaml.load(content)

