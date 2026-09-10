# XML User Directory

A user directory service backed by XML data, with XPath-based querying.

## Architecture

app.py → UserService → QueryBuilder + XMLRepository → lxml

## Install

pip install -r requirements.txt

## Run

python app.py

Server starts on http://127.0.0.1:5203

## Endpoints

- GET /api/user/search?username=alice — Search by username
- GET /api/user/search_by_email?email=alice@example.com — Search by email
- GET /api/user/by_id/1 — Get user by ID
- GET /api/user/list — List all users

## Tests

python -m pytest test_app.py -v
