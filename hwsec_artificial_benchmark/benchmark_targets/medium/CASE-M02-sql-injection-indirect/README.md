# User Management Service

A Flask application with service/repository layers for managing user records.

## Install

pip install -r requirements.txt

## Run

python app.py

Server starts on http://127.0.0.1:5102

## Endpoints

- GET /api/users/search?pattern=ali — Search by username pattern
- GET /api/users/by_role/user — Filter by role
- GET /api/users/1 — Get user by ID

## Tests

python -m pytest test_app.py -v
