"""Deliberately vulnerable test server for self-testing the toolkit."""
import http.server, socketserver, urllib.parse, time, os

PORT = 8765

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        path = parsed.path

        if path == "/":
            body = "<html><head><title>VulnApp</title></head><body><h1>VulnApp</h1><a href='/search?q=test'>search</a> <form method=GET action=/search><input name=q></form></body></html>"
            self._send(200, body, "text/html")
            return
        if path == "/search":
            q = qs.get("q", [""])[0]
            # reflected XSS (unencoded)
            body = f"<html><body>Results for: {q}</body></html>"
            self._send(200, body, "text/html")
            return
        if path == "/user":
            uid = qs.get("id", ["1"])[0]
            # SQL error if quote
            if "'" in uid:
                body = "You have an error in your SQL syntax; mysql_fetch_array()"
            else:
                body = f"User {uid}: alice"
            self._send(200, body, "text/html")
            return
        if path == "/page":
            f = qs.get("file", ["home"])[0]
            if "etc/passwd" in f or ".." in f:
                body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh"
            else:
                body = f"Page: {f}"
            self._send(200, body, "text/html")
            return
        if path == "/go":
            to = qs.get("next", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", to)
            self.end_headers()
            return
        if path == "/fetch":
            u = qs.get("url", [""])[0]
            if "169.254" in u or "127.0.0.1" in u or "localhost" in u:
                body = "ami-id: ami-123\ninstance-id: i-abc"
            else:
                body = "fetched"
            self._send(200, body, "text/html")
            return
        if path == "/tpl":
            t = qs.get("name", [""])[0]
            if "{{7*7}}" in t:
                body = "Hello 49"
            else:
                body = f"Hello {t}"
            self._send(200, body, "text/html")
            return
        if path == "/cmd":
            c = qs.get("ip", [""])[0]
            if ";" in c or "|" in c:
                body = "uid=33(www-data) gid=33(www-data)"
            else:
                body = "ping ok"
            self._send(200, body, "text/html")
            return
        if path == "/.env":
            self._send(200, "DB_PASSWORD=secret123\nAPI_KEY=abc", "text/plain")
            return
        if path == "/cors":
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        # headers
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.end_headers()
        self.wfile.write(b"ok")

    def _send(self, code, body, ct):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), H) as httpd:
        print(f"Vuln server on {PORT}")
        httpd.serve_forever()
