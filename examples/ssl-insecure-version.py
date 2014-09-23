import ssl
from pyOpenSSL import SSL

ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv2)
ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv23)
SSL.Context(method=SSL.SSLv2_METHOD)
SSL.Context(method=SSL.SSLv23_METHOD)

herp_derp(ssl_version=ssl.PROTOCOL_SSLv2)
herp_derp(ssl_version=ssl.PROTOCOL_SSLv23)
herp_derp(method=SSL.SSLv2_METHOD)
herp_derp(method=SSL.SSLv23_METHOD)

# strict tests
ssl.wrap_socket(ssl_version=ssl.PROTOCOL_SSLv3)
ssl.wrap_socket(ssl_version=ssl.PROTOCOL_TLSv1)
SSL.Context(method=SSL.SSLv3_METHOD)
SSL.Context(method=SSL.TLSv1_METHOD)

herp_derp(ssl_version=ssl.PROTOCOL_SSLv3)
herp_derp(ssl_version=ssl.PROTOCOL_TLSv1)
herp_derp(method=SSL.SSLv3_METHOD)
herp_derp(method=SSL.TLSv1_METHOD)

ssl.wrap_socket()