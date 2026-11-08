#!/usr/bin/env python3
"""Northwind Shop - a DELIBERATELY VULNERABLE web app for Lab 06.
Vulnerabilities (OWASP Top 10 2021): SQLi (A03), Broken Access Control / IDOR (A01),
OS Command Injection (A03), Path Traversal (A01/A05), and reflected XSS (A03, bonus).
Do not copy these patterns into real code."""
import html
import sqlite3
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = "/srv/app.db"


def flag(name):
    return open(f"/srv/flags/{name}.txt").read().strip()


def build_db():
    c = sqlite3.connect(DB)
    c.executescript("""
        DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS products; DROP TABLE IF EXISTS secrets;
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, note TEXT);
        CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price TEXT);
        CREATE TABLE secrets(id INTEGER PRIMARY KEY, flag TEXT);
    """)
    c.executemany("INSERT INTO users VALUES (?,?,?,?,?)", [
        (1, "admin", "S3cr3t-" + flag("sqli_login")[:6], "admin", "-"),
        (2, "alice", "password123", "user", "Remember to update the catalogue."),
        (3, "bob",   "hunter2",     "user", "My private note: " + flag("idor")),
        (4, "carol", "sunshine",    "user", "Lunch at 1pm."),
    ])
    c.executemany("INSERT INTO products VALUES (?,?,?)", [
        (1, "Widget", "$9.99"), (2, "Gadget", "$14.50"), (3, "Gizmo", "$7.25"),
        (4, "Sprocket", "$3.10"), (5, "Cog", "$1.00")])
    c.execute("INSERT INTO secrets VALUES (1,?)", (flag("sqli_union"),))
    c.commit(); c.close()


PAGE = """<!doctype html><html><head><meta charset=utf-8><title>Northwind Shop</title>
<style>body{{font:15px system-ui;max-width:760px;margin:30px auto;padding:0 16px;color:#16202a}}
a{{color:#0f7b6c}}nav a{{margin-right:14px}}input{{padding:6px}}pre{{background:#eee;padding:10px;overflow:auto}}
.box{{border:1px solid #ccc;border-radius:8px;padding:14px;margin:12px 0}}</style></head>
<body><h1>Northwind Shop</h1>
<nav><a href="/">home</a><a href="/search?q=widget">search</a><a href="/login">login</a>
<a href="/account?id=2">my account</a><a href="/tools">network tools</a><a href="/download?file=catalogue.txt">downloads</a></nav>
<hr>{body}</body></html>"""


def render(body):
    return PAGE.format(body=body).encode()


class H(BaseHTTPRequestHandler):
    server_version = "NorthwindShop/1.0"

    def send(self, body, code=200, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def db(self):
        return sqlite3.connect(DB)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        path = u.path

        if path == "/":
            self.send(render("<p>Welcome to the Northwind Shop staff portal.</p>"
                             "<!-- TODO: remove debug /tools and /download before launch -->"))

        elif path == "/login":
            self.send(render(
                '<h2>Staff login</h2><form method=POST action=/login>'
                'Username <input name=username><br><br>'
                'Password <input name=password type=password><br><br>'
                '<button>Log in</button></form>'))

        elif path == "/search":
            term = q.get("q", [""])[0]
            # VULNERABLE: string-concatenated SQL (SQLi), result reflected unescaped (XSS)
            sql = "SELECT name, price FROM products WHERE name LIKE '%" + term + "%'"
            rows, err = [], None
            try:
                con = self.db(); rows = con.execute(sql).fetchall(); con.close()
            except Exception as e:
                err = str(e)
            out = "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td></tr>" for r in rows)
            body = (f"<h2>Search results for: {term}</h2>"      # reflected (XSS bonus)
                    f"<table border=1><tr><th>Product</th><th>Price</th></tr>{out}</table>")
            if err:
                body += f"<pre>SQL error: {html.escape(err)}</pre>"   # verbose errors help SQLi
            self.send(render(body))

        elif path == "/account":
            # VULNERABLE: no authorization check - any id can be requested (IDOR)
            uid = q.get("id", ["2"])[0]
            try:
                con = self.db()
                row = con.execute("SELECT username, role, note FROM users WHERE id=?", (uid,)).fetchone()
                con.close()
            except Exception:
                row = None
            if row:
                self.send(render(f"<h2>Account: {html.escape(row[0])}</h2>"
                                 f"<div class=box>Role: {html.escape(row[1])}<br>"
                                 f"Note: {html.escape(row[2])}</div>"
                                 "<p>Tip: your account id is in the URL.</p>"))
            else:
                self.send(render("<p>No such account.</p>"))

        elif path == "/tools":
            self.send(render('<h2>Network tools</h2><form action=/tools/ping>'
                             'Host to ping <input name=host value=127.0.0.1>'
                             '<button>Ping</button></form>'))

        elif path == "/tools/ping":
            host = q.get("host", ["127.0.0.1"])[0]
            # VULNERABLE: user input passed to a shell (OS command injection)
            try:
                out = subprocess.run("ping -c 1 " + host, shell=True,
                                     capture_output=True, text=True, timeout=8)
                res = out.stdout + out.stderr
            except Exception as e:
                res = str(e)
            self.send(render(f"<h2>Ping {html.escape(host)}</h2><pre>{html.escape(res)}</pre>"))

        elif path == "/download":
            name = q.get("file", ["catalogue.txt"])[0]
            # VULNERABLE: path concatenated without sanitisation (path traversal / LFI)
            try:
                with open("/srv/files/" + name, "rb") as f:
                    data = f.read()
                self.send(data, ctype="text/plain")
            except Exception as e:
                self.send(render(f"<pre>Error: {html.escape(str(e))}</pre>"), code=404)

        else:
            self.send(render("<p>Not found.</p>"), code=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = urllib.parse.parse_qs(self.rfile.read(length).decode())
        if self.path == "/login":
            user = data.get("username", [""])[0]
            pw = data.get("password", [""])[0]
            # VULNERABLE: string-concatenated auth query (SQLi auth bypass)
            sql = (f"SELECT username, role FROM users "
                   f"WHERE username='{user}' AND password='{pw}'")
            try:
                con = self.db(); row = con.execute(sql).fetchone(); con.close()
            except Exception:
                row = None
            if row:
                extra = ""
                if row[1] == "admin":
                    extra = (f"<div class=box><b>Admin dashboard</b><br>"
                             f"Welcome, administrator. Flag: {flag('sqli_login')}</div>")
                self.send(render(f"<h2>Logged in as {html.escape(row[0])} "
                                 f"({html.escape(row[1])})</h2>{extra}"))
            else:
                self.send(render("<p>Invalid credentials.</p>"), code=401)
        else:
            self.send(render("<p>Not found.</p>"), code=404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    build_db()
    ThreadingHTTPServer(("0.0.0.0", 80), H).serve_forever()
