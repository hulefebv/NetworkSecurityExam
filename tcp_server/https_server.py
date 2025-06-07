import http.server
import ssl

server_address = ('10.0.1.3', 443)
handler = http.server.SimpleHTTPRequestHandler
httpd = http.server.HTTPServer(server_address, handler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile='certs/cert.pem', keyfile='certs/key.pem')

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("Serving HTTPS on https://10.0.1.3:443")
httpd.serve_forever()
