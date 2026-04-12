# Test cases for B622: logging of sensitive information

import logging

# B622: logging password
logging.debug("Password: %s", password)

# B622: logging secret
logging.info("Secret is %s", api_secret)

# B622: print token
print(f"Token: {auth_token}")

# B622: logging with keyword arg
logging.warning("Credentials: %s", credentials=credentials)

# B622: print api_key
print("The API key is", api_key)

# B622: logging private_key
logger.error("Key: %s", private_key)

# B622: logging access_key
logging.info("Access: %s" % access_key)

# No issue - safe logging
logging.debug("User logged in: %s", username)
print("Hello world")
logging.info("Request completed in %s seconds", elapsed)

# No issue - safe variable names
logging.debug("Count: %s", total_count)
print(f"Name: {user_name}")

# B622: pprint sensitive info
import pprint
pprint.pprint({"token": token})

# B622: logging database URL with password
logging.debug("DB URL: %s", database_url)

# B622: f-string with sensitive
print(f"Connecting with {db_password}")

# B622: keyring retrieval then logged
password = keyring.get_password("service", "user")
logging.debug("Got password: %s", password)
