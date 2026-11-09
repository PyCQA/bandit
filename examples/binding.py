import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 31137))
s.bind(('192.168.0.1', 8080))
s.bind(('', 31137))  # empty string == INADDR_ANY
s.bind(['', 31137])  # list form, also accepted by socket.bind

# Plain empty-string literals outside of a ``bind`` call must not be flagged.
default_host = ''
host_options = ('localhost', 'example.com')
