"""HTTPS server for the Safari UI test page (scripts/ios_simulator_checks.sh). Usage: serve.py <cert> <key> <port>.
Binds 127.0.0.1 only; the simulator reaches it as loginlab.localhost and 1oginlab.localhost."""
import http.server
import os
import ssl
import sys

cert, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
os.chdir(os.path.dirname(os.path.abspath(__file__)))
server = http.server.ThreadingHTTPServer(("127.0.0.1", port), http.server.SimpleHTTPRequestHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
