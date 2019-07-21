def someFunction(user, password="Admin"):
    print("Hi " + user)

def someFunction2(password):
    if password == "root":
        print("OK, logged in")

def noMatch(password):
    if password == '':
        print("No password!")

def NoMatch2(password):
    if password == "ajklawejrkl42348swfgkg":
        print("Nice password!")

def doLogin(password="blerg"):
    pass

def NoMatch3(a, b):
    pass

doLogin(password="blerg")
password = "blerg"
d["password"] = "blerg"

EMAIL_PASSWORD = "secret"
email_pwd = 'emails_secret'
my_secret_password_for_email = 'd6s$f9g!j8mg7hw?n&2'
passphrase='1234'

user= {
  'username': 'donotdetect',
  'passWord': 'detectmeisecret'
}

nomatchnested = {
  'nomatch': 'dontdetect',
  'pasS': {
    'nomatch2': 'nomatch3'
  }
}

matchnested ={
  'nomatch': 'dontdetect',
  'nomatch2': {
    'user': 'nomatch3',
    'PASSphrase': 'secretpassword'
  },
  'pwd': 'nested_pwd'
}

log({"server": server, "password": 'pass', "user": user})
