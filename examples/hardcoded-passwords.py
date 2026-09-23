#-----------------------------------------------------------------------------
# ASSIGNMENTS
#-----------------------------------------------------------------------------

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
password = "this_string"

# not!
a = "password"


# not!
password.a = "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a.password = "this_string"

# not!
a.b = "password"

# not!
password['b'] = "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a['password'] = "this_string"

# not!
a['b'] = "password"


# not!
password[b] = "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a[password] = "this_string"

# not!
a[b] = "password"


# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
password = b.c = d['e'] = f[g] = "this_string"

# not!
a = password.c = d['e'] = f[g] = "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a = b.password = d['e'] = f[g] = "this_string"

# not!
a = b.c = password['e'] = f[g] = "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a = b.c = d['password'] = f[g] = "this_string"

# not!
a = b.c = d['e'] = password[g] = "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a = b.c = d['e'] = f[password] = "this_string"

# not!
a = b.c = d['e'] = f[g] = "password"


# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
class SomeClass:
    password = "this_string"


#-----------------------------------------------------------------------------
# ANNOTATED ASSIGNMENTS
#-----------------------------------------------------------------------------

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
password: str = "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
password: "str" = "this_string"

# not!
a: password = "this_string"

# not!
a: "password" = "this_string"

# not!
a: str = "password"

# not!
a: "str" = "password"


# not!
password.b: str = "this_string"

# not!
password.b: "str" = "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a.password: str = "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a.password: "str" = "this_string"

# not!
a.b: password = "this_string"

# not!
a.b: "password" = "this_string"

# not!
a.b: str = "password"

# not!
a.b: "str" = "password"


# not!
password["b"]: str = "this_string"

# not!
password["b"]: "str" = "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a["password"]: str = "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a["password"]: "str" = "this_string"

# not!
a["b"]: password = "this_string"

# not!
a["b"]: "password" = "this_string"

# not!
a["b"]: str = "password"

# not!
a["b"]: "str" = "password"


# not!
password[b]: str = "this_string"

# not!
password[b]: "str" = "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a[password]: str = "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a[password]: "str" = "this_string"

# not!
a[b]: password = "this_string"

# not!
a[b]: "password" = "this_string"

# not!
a[b]: str = "password"

# not!
a[b]: "str" = "password"


#-----------------------------------------------------------------------------
# DICTIONARIES
#-----------------------------------------------------------------------------

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
{"password": "this_string"}

# not!
{"a": "password"}


# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
{password: "this_string"}

# not!
{a: "password"}


#-----------------------------------------------------------------------------
# COMPARISONS
#-----------------------------------------------------------------------------

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
password == "this_string"

# not!
a == "password"


# not!
password.b == "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a.password == "this_string"

# not!
a.b == "password"


# not!
password["b"] == "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a["password"] == "this_string"

# not!
a["b"] == "password"


# not!
password[b] == "this_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
a[password] == "this_string"

# not!
a[b] == "password"


# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
password != "this_string"

# not!
a != "password"


# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
"this_string" == password

# not!
"password" == b


# not!
password == b == c

# not!
a == password == c

# not!
a == b == password

# Possible hardcoded password: 'third_string'
# Severity: Low   Confidence: Medium
password == b == "third_string"

# Possible hardcoded password: 'third_string'
# Severity: Low   Confidence: Medium
a == password == "third_string"

# not!
a == b == "password"

# Possible hardcoded password: 'other_string'
# Severity: Low   Confidence: Medium
password == "other_string" == c

# not!
a == "password" == c

# Possible hardcoded password: 'other_string'
# Severity: Low   Confidence: Medium
a == "other_string" == password

# Possible hardcoded password: 'other_string'
# Severity: Low   Confidence: Medium
# Possible hardcoded password: 'third_string'
# Severity: Low   Confidence: Medium
password == "other_string" == "third_string"

# not!
a == "password" == "third_string"

# not!
a == "other_string" == "password"

# not!
"password" == b == c

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
"this_string" == password == c

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
"this_string" == b == password

# not!
"password" == b == "third_string"

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
# Possible hardcoded password: 'third_string'
# Severity: Low   Confidence: Medium
"this_string" == password == "third_string"

# not!
"this_string" == b == "password"

# not!
"password" == "other_string" == c

# not!
"this_string" == "password" == c

# Possible hardcoded password: 'this_string'
# Severity: Low   Confidence: Medium
# Possible hardcoded password: 'other_string'
# Severity: Low   Confidence: Medium
"this_string" == "other_string" == password

# not!
"password" == "other_string" == "third_string"

# not!
"this_string" == "password" == "third_string"

# not!
"this_string" == "other_string" == "password"


#-----------------------------------------------------------------------------
# FUNCTION CALLS
#-----------------------------------------------------------------------------

# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
doLogin(password="blerg")


#-----------------------------------------------------------------------------
# FUNCTION DEFINITIONS
#-----------------------------------------------------------------------------

# Possible hardcoded password: 'Admin'
# Severity: Low   Confidence: Medium
def someFunction(user, password="Admin"):
    print("Hi " + user)


# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
def doLogin(password="blerg"):
    pass


def NoMatch3(a, b):
    pass


#-----------------------------------------------------------------------------
# REPORTED ISSUES
#-----------------------------------------------------------------------------

# https://github.com/PyCQA/bandit/issues/313

# Possible hardcoded password: 'pass'
# Severity: Low   Confidence: Medium
log({"server": server, "password": 'pass', "user": user})

# not!
log({"server": server, "password": password, "user": user})

# Possible hardcoded password: 'pass'
# Severity: Low   Confidence: Medium
log(password='pass')


# https://github.com/PyCQA/bandit/issues/386

# Possible hardcoded password: 'secret'
# Severity: Low   Confidence: Medium
EMAIL_PASSWORD = "secret"

# Possible hardcoded password: 'emails_secret'
# Severity: Low   Confidence: Medium
email_pwd = 'emails_secret'


# https://github.com/PyCQA/bandit/issues/551

# Possible hardcoded password: 'aaaaaaa'
# Severity: Low   Confidence: Medium
app.config['SECRET_KEY'] = 'aaaaaaa'


# https://github.com/PyCQA/bandit/issues/605

# Possible hardcoded password: 'root'
# Severity: Low   Confidence: Medium
def fooBar(password):
    if password == "root":
        print("OK, logged in")


# https://github.com/PyCQA/bandit/issues/639

# Possible hardcoded password: '1238aoufhz8xyf3jr;'
# Severity: Low   Confidence: Medium
password = "1238aoufhz8xyf3jr;"


# https://github.com/PyCQA/bandit/issues/642

# Possible hardcoded password: 'password'
# Severity: Low   Confidence: Medium
class MyConfig:
    my_password: str = 'password'


# https://github.com/PyCQA/bandit/issues/759

# Possible hardcoded password: '12123123'
# Severity: Low   Confidence: Medium
password = "12123123"

# Possible hardcoded password: '12123123'
# Severity: Low   Confidence: Medium
self.password = "12123123"


# https://github.com/PyCQA/bandit/issues/1267

# Possible hardcoded password: '12345'
# Severity: Low   Confidence: Medium
{"password": "12345"}


#-----------------------------------------------------------------------------
# OTHER
#-----------------------------------------------------------------------------

# TODO: what's the purpose of this example?
# Possible hardcoded password: None
# Severity: High   Confidence: High
def __init__(self, auth_scheme, auth_token=None, auth_username=None, auth_password=None, auth_link=None, **kwargs):
    self.auth_scheme = auth_scheme
    self.auth_token = auth_token
    self.auth_username = auth_username
    self.auth_password = auth_password
    self.auth_link = auth_link
    self.kwargs = kwargs

# TODO: what's the purpose of this example?
# Possible hardcoded password: None
# Severity: High   Confidence: High
from oslo_config import cfg
cfg.StrOpt(
    'metadata_proxy_shared_secret',
    default='',
    secret=True,
)
