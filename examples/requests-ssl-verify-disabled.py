import requests

requests.get('https://gmail.com', verify=True)
requests.get('https://gmail.com', verify=False)
requests.post('https://gmail.com', verify=True)
requests.post('https://gmail.com', verify=False)
