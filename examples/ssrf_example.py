import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/fetch")
def fetch():
    # Bad: request-controlled URL
    url = request.args.get("url")
    return requests.get(url).text

@app.route("/fetch2")
def fetch2():
    # Bad: direct request.args usage
    return requests.get(request.args.get("url")).text

@app.route("/safe")
def safe():
    # Good: literal URL
    return requests.get("https://example.com").text
