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

# Possible hardcoded password: 'password'
# Severity: Low   Confidence: Medium
# https://github.com/PyCQA/bandit/issues/642
class MyConfig:
    my_password: str = 'password'


# Possible hardcoded password: 'admin123'
# Severity: Low   Confidence: Medium
config.password: str = "admin123"


# Possible hardcoded password: 'admin123'
# Severity: Low   Confidence: Medium
d["password"]: str = "admin123"


# Possible hardcoded password: 'admin123'
# Severity: Low   Confidence: Medium
d[password]: str = 'admin123'


#-----------------------------------------------------------------------------
# DICTIONARIES
#-----------------------------------------------------------------------------

# Possible hardcoded password: 'pass'
# Severity: Low   Confidence: Medium
# https://github.com/PyCQA/bandit/issues/313
log({"server": server, "password": 'pass', "user": user})


# ... but not:
log({"server": server, "password": password, "user": user})


# Possible hardcoded password: '12345'
# Severity: Low   Confidence: Medium
# https://github.com/PyCQA/bandit/issues/1267
info = {"password": "12345"}


# ... but not:
info = {"password": password}


#-----------------------------------------------------------------------------
# COMMPARISONS
#-----------------------------------------------------------------------------

def someFunction2(password):
    # Possible hardcoded password: 'root'
    # Severity: Low   Confidence: Medium
    if password == "root":
        print("OK, logged in")


def noMatch(password):
    # Possible hardcoded password: ''
    # Severity: Low   Confidence: Medium
    if password == '':
        print("No password!")


def NoMatch2(password):
    # Possible hardcoded password: 'ajklawejrkl42348swfgkg'
    # Severity: Low   Confidence: Medium
    if password == "ajklawejrkl42348swfgkg":
        print("Nice password!")


def noMatchObject():
    obj = SomeClass()
    # Possible hardcoded password: 'this cool password'
    # Severity: Low   Confidence: Medium
    if obj.password == "this cool password":
        print(obj.password)


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
