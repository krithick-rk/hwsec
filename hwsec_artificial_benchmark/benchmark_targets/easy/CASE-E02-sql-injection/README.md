# User Directory Service

A small Flask application for searching user records.

## Install

pip install -r requirements.txt

## Run

python app.py

Server starts on http://127.0.0.1:5002

## Endpoints

- GET /api/users/search?username=alice — Search by username
- GET /api/users/1 — Get user by ID

## Tests

python -m pytest test_app.py -v
