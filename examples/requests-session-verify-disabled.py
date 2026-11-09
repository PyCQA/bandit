import httpx
import requests

# B501: Session/Client instance methods with verify=False
session = requests.Session()
session.get("https://gmail.com", timeout=30, verify=False)
session.post("https://gmail.com", timeout=30, verify=False)

with requests.Session() as scoped_session:
    scoped_session.put("https://gmail.com", timeout=30, verify=False)
    scoped_session.delete("https://gmail.com", timeout=30, verify=False)

client = httpx.Client(timeout=30)
client.get("https://gmail.com", timeout=30, verify=False)
client.post("https://gmail.com", timeout=30, verify=False)

# B501: Chained constructor calls with verify=False
requests.Session().get("https://gmail.com", timeout=30, verify=False)
httpx.Client().post("https://gmail.com", timeout=30, verify=False)

# Okay: verify=True or not specified
session_safe = requests.Session()
session_safe.get("https://gmail.com", timeout=30, verify=True)
requests.Session().get("https://gmail.com", timeout=30)
