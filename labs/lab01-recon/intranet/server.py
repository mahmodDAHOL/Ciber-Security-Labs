import base64
import http.server

USER = "alice"
PASSWORD = open("/secrets/password").read().strip()
FLAG = open("/flag").read().strip()
EXPECTED = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()

PAGES = {
    "/": "<h1>Northwind Intranet</h1><ul><li><a href='/status'>status</a></li>"
         "<li><a href='/admin/flag.txt'>admin</a></li></ul>\n",
    "/status": "status: ok\n",
    "/admin/flag.txt": FLAG + "\n",
}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "IntranetPortal/1.0"
    sys_version = ""

    def reply(self, code, body, headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html" if body.startswith("<") else "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.headers.get("Authorization", "") != EXPECTED:
            return self.reply(401, "Authentication required\n",
                              [("WWW-Authenticate", 'Basic realm="Northwind Intranet"')])
        body = PAGES.get(self.path)
        if body is None:
            return self.reply(404, "Not found\n")
        self.reply(200, body)

    def log_message(self, *args):
        pass


http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
