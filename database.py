"""MediConnect database layer (SQLite, no extra packages needed)."""
import hashlib
import hmac
import os
import secrets
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mediconnect.db")

# role -> table name. Only these values are ever used in SQL (never user input).
ROLE_TABLES = {
    "doctor": "doctors",
    "patient": "patients",
    "pharmacist": "pharmacists",
}

# Columns shown on the dashboard for each role (never includes the password).
PROFILE_FIELDS = {
    "doctor": ["full_name", "username", "specialty", "hospital", "license_no"],
    "patient": ["full_name", "username", "phone", "date_of_birth", "blood_group"],
    "pharmacist": ["full_name", "username", "pharmacy_name", "license_no"],
}


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password, salt=None):
    """PBKDF2-SHA256. Returns 'salt$hash' so one column stores both."""
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return f"{salt}${digest.hex()}"


def verify_password(password, stored):
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, salt), stored)


# Used so a wrong username takes as long as a wrong password (no user probing).
_DUMMY_HASH = hash_password("dummy-password")


def init_db():
    conn = connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS doctors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            specialty TEXT NOT NULL,
            hospital TEXT NOT NULL,
            license_no TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            date_of_birth TEXT NOT NULL,
            blood_group TEXT
        );
        CREATE TABLE IF NOT EXISTS pharmacists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            pharmacy_name TEXT NOT NULL,
            license_no TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            role TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        """
    )
    if conn.execute("SELECT COUNT(*) FROM doctors").fetchone()[0] == 0:
        seed(conn)
    conn.commit()
    conn.close()


def seed(conn):
    """Demo accounts so you can log in straight away. Delete these before real use."""
    doctors = [
        ("dr.shinde", "doctor123", "Dr. Manish Shinde", "Cardiology", "City Care Hospital", "MH-DOC-1001"),
        ("dr.singh", "doctor123", "Dr. Roshni Singh", "Pediatrics", "City Care Hospital", "MH-DOC-1002"),
        ("dr.choudhary", "doctor123", "Dr. Nancy Choudhary", "Neurology", "Sunrise Medical Centre", "MP-DOC-1003"),
    ]
    patients = [
        ("sarah.malik", "patient123", "Sarah Malik", "9876500001", "1994-03-12", "B+"),
        ("ram.kapoor", "patient123", "Ram Kapoor", "9876500002", "2016-08-21", "O+"),
        ("rohan.mehta", "patient123", "Rohan Mehta", "9876500003", "1988-11-05", "A-"),
    ]
    pharmacists = [
        ("healthplus", "pharma123", "Amit Verma", "HealthPlus Pharmacy", "PH-2001"),
        ("wellness", "pharma123", "Neha Joshi", "Wellness Chemist", "PH-2002"),
        ("carepharmacy", "pharma123", "Imran Khan", "Care Pharmacy", "PH-2003"),
    ]
    for u, p, *rest in doctors:
        conn.execute(
            "INSERT INTO doctors (username, password_hash, full_name, specialty, hospital, license_no) VALUES (?,?,?,?,?,?)",
            (u, hash_password(p), *rest),
        )
    for u, p, *rest in patients:
        conn.execute(
            "INSERT INTO patients (username, password_hash, full_name, phone, date_of_birth, blood_group) VALUES (?,?,?,?,?,?)",
            (u, hash_password(p), *rest),
        )
    for u, p, *rest in pharmacists:
        conn.execute(
            "INSERT INTO pharmacists (username, password_hash, full_name, pharmacy_name, license_no) VALUES (?,?,?,?,?)",
            (u, hash_password(p), *rest),
        )


def authenticate(role, username, password):
    """Return the user row if credentials match this role's table, else None."""
    table = ROLE_TABLES.get(role)
    if not table:
        return None
    conn = connect()
    row = conn.execute(f"SELECT * FROM {table} WHERE username = ?", (username.strip().lower(),)).fetchone()
    conn.close()
    if row is None:
        verify_password(password, _DUMMY_HASH)  # equalise timing
        return None
    return row if verify_password(password, row["password_hash"]) else None


def get_user(role, user_id):
    table = ROLE_TABLES.get(role)
    if not table:
        return None
    conn = connect()
    row = conn.execute(f"SELECT * FROM {table} WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


# ---------------------------------------------------------------------------
# Sign-up
# ---------------------------------------------------------------------------
# Extra fields each role fills in when creating an account: (column, required?)
SIGNUP_FIELDS = {
    "doctor": [("specialty", True), ("hospital", True), ("license_no", True)],
    "patient": [("phone", True), ("date_of_birth", True), ("blood_group", False)],
    "pharmacist": [("pharmacy_name", True), ("license_no", True)],
}


class SignupError(Exception):
    """Raised with a user-friendly message when sign-up data is not acceptable."""


def create_user(role, data):
    """Validate and insert a new account. Returns the new user row."""
    import re

    table = ROLE_TABLES.get(role)
    if not table:
        raise SignupError("Choose a role.")

    full_name = str(data.get("full_name", "")).strip()
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))

    if len(full_name) < 2:
        raise SignupError("Enter your full name.")
    if not re.fullmatch(r"[a-z0-9._-]{3,30}", username):
        raise SignupError("Username must be 3-30 characters: letters, numbers, dot, dash or underscore.")
    if len(password) < 8:
        raise SignupError("Password must be at least 8 characters.")
    if len(password) > 128:
        raise SignupError("Password is too long (max 128 characters).")

    extra = {}
    for col, required in SIGNUP_FIELDS[role]:
        value = str(data.get(col, "")).strip()[:120]
        if required and not value:
            raise SignupError("Fill in all required fields.")
        extra[col] = value or None

    if role == "patient":
        if not re.fullmatch(r"\+?[0-9 ()-]{7,15}", extra["phone"]):
            raise SignupError("Enter a valid phone number.")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", extra["date_of_birth"]):
            raise SignupError("Enter your date of birth.")

    columns = ["username", "password_hash", "full_name"] + list(extra)
    values = [username, hash_password(password), full_name] + list(extra.values())
    sql = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join('?' * len(columns))})"

    conn = connect()
    try:
        cur = conn.execute(sql, values)
        conn.commit()
        row = conn.execute(f"SELECT * FROM {table} WHERE id = ?", (cur.lastrowid,)).fetchone()
        return row
    except sqlite3.IntegrityError as e:
        if "username" in str(e):
            raise SignupError("That username is taken. Try another one.")
        if "license_no" in str(e):
            raise SignupError("An account with this license number already exists.")
        raise SignupError("Could not create the account.")
    finally:
        conn.close()
