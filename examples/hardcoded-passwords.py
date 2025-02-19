# Possible hardcoded password: 'class_password'
# Severity: Low   Confidence: Medium
class SomeClass:
    password = "class_password"

# Possible hardcoded password: 'Admin'
# Severity: Low   Confidence: Medium
def someFunction(user, password="Admin"):
    print("Hi " + user)

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

# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
def doLogin(password="blerg"):
    pass

def NoMatch3(a, b):
    pass

# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
doLogin(password="blerg")

# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
password = "blerg"

# Possible hardcoded password: 'blerg'
# Severity: Low   Confidence: Medium
password["password"] = "blerg"

# Possible hardcoded password: 'secret'
# Severity: Low   Confidence: Medium
EMAIL_PASSWORD = "secret"

# Possible hardcoded password: 'emails_secret'
# Severity: Low   Confidence: Medium
email_pwd = 'emails_secret'

# Possible hardcoded password: 'd6s$f9g!j8mg7hw?n&2'
# Severity: Low   Confidence: Medium
my_secret_password_for_email = 'd6s$f9g!j8mg7hw?n&2'

# Possible hardcoded password: '1234'
# Severity: Low   Confidence: Medium
passphrase='1234'

# Possible hardcoded password: None
# Severity: High   Confidence: High
def __init__(self, auth_scheme, auth_token=None, auth_username=None, auth_password=None, auth_link=None, **kwargs):
    self.auth_scheme = auth_scheme
    self.auth_token = auth_token
    self.auth_username = auth_username
    self.auth_password = auth_password
    self.auth_link = auth_link
    self.kwargs = kwargs
