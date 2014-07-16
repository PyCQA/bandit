import requests as r

r.get('https://gmail.com', verify=True)
r.get('https://gmail.com', verify=False)
r.post('https://gmail.com', verify=True)
r.post('https://gmail.com', verify=False)
