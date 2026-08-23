import json, ssl, sys, gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CATALOG = [
    {"id": 101, "sku": "LG-KEYPAD", "name": "Deadbolt Keypad", "price": 189.00, "stock": 42},
    {"id": 102, "sku": "LG-SENSOR", "name": "Door Sensor (2-pack)", "price": 49.50, "stock": 310},
    {"id": 103, "sku": "LG-HUB", "name": "Gateway Hub", "price": 129.00, "stock": 7},
]

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.25.3"
    sys_version = ""

    def log_message(self, *a): pass

    def _send(self, code, body=b"", ctype="application/json", extra=None, gz=False):
        if gz:
            body = gzip.compress(body)
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if gz:
            self.send_header("Content-Encoding", "gzip")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj, extra=None, gz=False):
        self._send(code, json.dumps(obj, indent=2).encode(), "application/json", extra, gz)

    def do_GET(self):
        p = self.path.split("?")[0]
        auth = self.headers.get("Authorization", "")
        if p == "/":
            html = b"""<!doctype html>
<html><head><title>Northwind Locks</title>
<link rel="stylesheet" href="/static/app.css"></head>
<body><h1>Northwind Locks</h1>
<p>Smart locks for people who read the changelog.</p>
<a href="/login">Sign in</a>
<script src="/static/app.js"></script></body></html>"""
            return self._send(200, html, "text/html; charset=utf-8")
        if p == "/static/app.css":
            return self._send(200, b"body{font:16px/1.5 system-ui;margin:3rem auto;max-width:40rem}", "text/css")
        if p == "/static/app.js":
            return self._send(200, b"window.API_BASE='http://api.shop.localtest.me:8000';\n", "application/javascript")
        if p == "/login":
            return self._send(200, b"<!doctype html><form method=post action=/api/v1/session>"
                                   b"<input name=email><input name=password type=password></form>",
                              "text/html; charset=utf-8")
        if p == "/api/v1/products":
            return self._json(200, {"products": CATALOG, "total": len(CATALOG)}, gz=True)
        if p.startswith("/api/v1/products/"):
            pid = p.rsplit("/", 1)[-1]
            hit = [c for c in CATALOG if str(c["id"]) == pid]
            if hit:
                return self._json(200, hit[0])
            return self._json(404, {"error": "not_found", "resource": "product", "id": pid})
        if p == "/api/v1/cart":
            return self._json(200, {"items": [{"sku": "LG-HUB", "qty": 1}], "subtotal": 129.00})
        if p == "/api/v1/account":
            if not auth.startswith("Bearer "):
                return self._json(401, {"error": "unauthenticated"},
                                  {"WWW-Authenticate": "Bearer realm=\"api\""})
            return self._json(200, {"id": 4711, "email": "dana@example.com", "role": "customer",
                                    "mfa_enabled": False})
        if p.startswith("/api/v1/orders/"):
            oid = p.rsplit("/", 1)[-1]
            if not auth.startswith("Bearer "):
                return self._json(401, {"error": "unauthenticated"})
            return self._json(200, {"id": int(oid), "user_id": 4711, "total": 178.50,
                                    "status": "shipped",
                                    "address": {"line1": "12 Kirkgate", "city": "Leeds"}})
        if p == "/api/v1/admin/users":
            return self._json(403, {"error": "forbidden", "required_role": "admin"})
        if p == "/api/v1/reports/export":
            return self._json(500, {"error": "internal", "trace_id": "b91c4e2f"})
        if p == "/health":
            return self._json(200, {"ok": True})
        return self._json(404, {"error": "not_found", "path": p})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n)
        p = self.path.split("?")[0]
        if p == "/api/v1/session":
            return self._json(201, {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjQ3MTEsInJvbGUiOiJjdXN0b21lciJ9.s1g",
                                    "expires_in": 3600},
                              {"Set-Cookie": "sid=8f2b1c9d4a; Path=/; HttpOnly"})
        if p == "/api/v1/cart/items":
            return self._json(201, {"added": json.loads(raw or b"{}"), "subtotal": 258.00})
        return self._json(404, {"error": "not_found", "path": p})

    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n)
        return self._json(200, {"updated": json.loads(raw or b"{}"), "id": 4711})

port = int(sys.argv[1])
srv = ThreadingHTTPServer(("127.0.0.1", port), H)
if len(sys.argv) > 2 and sys.argv[2] == "tls":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(".vhsout/origin.crt", ".vhsout/origin.key")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
