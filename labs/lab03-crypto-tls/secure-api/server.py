import http.server
import ssl

FLAG = open("/flag").read()


class H(http.server.BaseHTTPRequestHandler):
    server_version = "secure-api/1.0"
    sys_version = ""

    def do_GET(self):
        # Reached only after the client presented a certificate signed by the Northwind CA
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(FLAG.encode())

    def log_message(self, *a):
        pass


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/app/server.crt", "/app/server.key")
ctx.load_verify_locations("/pki/ca.crt")
ctx.verify_mode = ssl.CERT_REQUIRED          # mutual TLS: the client must prove itself too
httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), H)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
