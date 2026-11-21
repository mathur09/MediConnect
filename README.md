# MediConnect
MediConnect: a connected healthcare platform linking patients, doctors and pharmacies, with role-based login and sign-up backed by a database.
# MediConnect – Login + Database (Step 1)

## Run
1. Install Python 3.8+ (no other packages needed).
2. In this folder run:  `python server.py`
3. Open http://localhost:8000

The database file `mediconnect.db` is created automatically on first run with demo accounts.
To reset it, stop the server, delete `mediconnect.db`, and start again.

## Demo accounts
| Role       | Username     | Password   |
|------------|--------------|------------|
| Patient    | sarah.malik  | patient123 |
| Doctor     | dr.shinde    | doctor123  |
| Pharmacist | healthplus   | pharma123  |
(More are in `database.py` → `seed()`.)

## Create an account
On the login page choose **Create account**, pick Patient / Doctor / Pharmacist and fill in the details for that role.
New users are signed in straight away. (Direct link: http://localhost:8000/#signup)

## How it works
Browser form -> POST /api/login {role, username, password}
-> server looks in the doctors / patients / pharmacists table -> checks the PBKDF2 password hash
-> creates a session cookie -> dashboard.html loads your profile from GET /api/me.

## Files
- database.py   tables, password hashing, demo data, login check
- server.py     web server + /api/login, /api/signup, /api/me, /api/logout
- static/       index.html (login), dashboard.html, style.css, logo.svg
