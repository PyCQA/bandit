import hashlib

import flask
import jinja2
from paramiko import client
import requests
import yaml
from yaml import load
from yaml import Loader

app = flask.Flask(__name__)


@app.route('/')
def main():
    # Test call within if statement
    if requests.get('https://google.com', verify=False):

        # Test complex call within dict of multiple lines
        yaml_dict = {
            "first": yaml.load("""
a: 1
b: 2
c: 3"""
),
        }

        load("{}")  # Test trailing comment

        # Newer PyYAML load() requires a Loader
        load("{}", Loader=Loader)

        # Test multiple calls on same line
        data = b"abcd"
        print(hashlib.md4(data),
            hashlib.md5(data), hashlib.sha(data),
            hashlib.sha1(data))

        # Test a call over multiple lines
        ssh_client = client.SSHClient()
        ssh_client.set_missing_host_key_policy(
            client.AutoAddPolicy  # This comment will get lost
        )

        jinja2.Environment(loader=templateLoader,
            load=templateLoader)

if debug:
    app.run()
else:
    app.run(debug=True)
main()
