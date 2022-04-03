import flask
from flask import Markup

user_input = "<script>alert(1)</script>"

# True: flask.Markup usage
flask.Markup(user_input)

# True: flask.Markup.unescape
flask.Markup(user_input).unescape()

# True: flask.Markup.escape.unescape
flask.Markup.escape(user_input).unescape()

# False: flask.Markup.escape
flask.Markup.escape(user_input)

# False: Markup.escape
Markup.escape(user_input)
