import http.server
import ssl

PAGE = (b"<h1>Northwind Intranet</h1>"
        b"<p>This site now uses TLS. Inspect our certificate.</p>")


class H(http.server.BaseHTTPRequestHandler):
    server_version = "intranet/2.0"
    sys_version = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *a):
        pass


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/app/srv.crt", "/app/srv.key")
httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), H)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
