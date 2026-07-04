from flask import Flask, request, send_file

app = Flask(__name__)

@app.route("/download")
def download():
    # Bad: request-controlled path
    path = request.args.get("path")
    return send_file(path)

@app.route("/download2")
def download2():
    # Bad: direct request.args usage
    return send_file(request.args.get("path"))

@app.route("/download3")
def download3():
    # Bad: request.form
    return send_file(request.form.get("file"))

@app.route("/safe")
def safe():
    # Good: literal path
    return send_file("static/data.csv")

@app.route("/safe2")
def safe2():
    # Good: variable not from request
    path = "/safe/path.txt"
    return send_file(path)
