"""MediConnect web server: serves the pages and the login API.

Run:  python server.py     then open  http://localhost:8000
Needs only Python 3.8+ (no pip installs).
"""
import json
import mimetypes
import os
import secrets
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import database as db

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SESSION_SECONDS = 60 * 60 * 8  # 8 hours
PORT = int(os.environ.get("PORT", 8000))


class Handler(BaseHTTPRequestHandler):
    # ---------- helpers ----------
    def send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return None

    def session_token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = cookies.SimpleCookie(raw)
        return jar["session"].value if "session" in jar else None

    def current_user(self):
        token = self.session_token()
        if not token:
            return None, None
        conn = db.connect()
        s = conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
        if s and s["expires_at"] < time.time():
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            s = None
        conn.close()
        if not s:
            return None, None
        return s["role"], db.get_user(s["role"], s["user_id"])

    # ---------- routes ----------
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/me":
            role, user = self.current_user()
            if not user:
                return self.send_json(401, {"error": "Not logged in."})
            profile = {f: user[f] for f in db.PROFILE_FIELDS[role]}
            return self.send_json(200, {"role": role, "profile": profile})
        self.serve_static(path)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/login":
            return self.login()
        if path == "/api/signup":
            return self.signup()
        if path == "/api/logout":
            token = self.session_token()
            if token:
                conn = db.connect()
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
                conn.close()
            return self.send_json(
                200, {"ok": True},
                {"Set-Cookie": "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"},
            )
        self.send_json(404, {"error": "Not found."})

    def login(self):
        data = self.read_json()
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "Invalid request."})
        role = str(data.get("role", ""))
        username = str(data.get("username", ""))
        password = str(data.get("password", ""))
        if role not in db.ROLE_TABLES or not username or not password:
            return self.send_json(400, {"error": "Choose a role and enter your username and password."})

        user = db.authenticate(role, username, password)
        if not user:
            return self.send_json(401, {"error": "Username or password is incorrect for this role."})

        self.start_session(role, user)

    def signup(self):
        data = self.read_json()
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "Invalid request."})
        role = str(data.get("role", ""))
        try:
            user = db.create_user(role, data)
        except db.SignupError as e:
            return self.send_json(400, {"error": str(e)})
        self.start_session(role, user, status=201)  # new users are signed in right away

    def start_session(self, role, user, status=200):
        token = secrets.token_urlsafe(32)
        conn = db.connect()
        conn.execute(
            "INSERT INTO sessions (token, role, user_id, expires_at) VALUES (?,?,?,?)",
            (token, role, user["id"], int(time.time()) + SESSION_SECONDS),
        )
        conn.commit()
        conn.close()
        self.send_json(
            status, {"ok": True, "role": role, "name": user["full_name"]},
            {"Set-Cookie": f"session={token}; Path=/; Max-Age={SESSION_SECONDS}; HttpOnly; SameSite=Lax"},
        )

    def serve_static(self, path):
        if path == "/":
            path = "/index.html"
        full = os.path.normpath(os.path.join(STATIC_DIR, path.lstrip("/")))
        if not full.startswith(STATIC_DIR) or not os.path.isfile(full):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
            return
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")


if __name__ == "__main__":
    db.init_db()
    print(f"MediConnect running at http://localhost:{PORT}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
