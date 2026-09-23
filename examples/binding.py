import socket

s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s1.bind(('0.0.0.0', 31137))

s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2.bind(('192.168.0.1', 8080))

s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s3.bind(('', 8080))  # empty string is also a wildcard bind
