# Authentication Service

A directory-based authentication service with user lookup and verification.
Uses an LDAP-style directory for credential management.

## Architecture

app.py → AuthService → LDAPService → MockLDAPRepository

## Install

pip install -r requirements.txt

## Run

python app.py

Server starts on http://127.0.0.1:5202

## Endpoints

- POST /api/auth/login — Authenticate user (body: {"username":"admin","password":"admin123"})
- GET  /api/auth/lookup?username=admin — Look up user by name
- GET  /api/auth/verify/1 — Verify user by employee number

## Tests

python -m pytest test_app.py -v
