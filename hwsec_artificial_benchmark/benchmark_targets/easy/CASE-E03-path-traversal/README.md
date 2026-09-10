# File Download Service

A small Flask application for serving files from a local directory.

## Install

pip install -r requirements.txt

## Run

python app.py

Server starts on http://127.0.0.1:5003

## Endpoints

- GET /api/files/download?filename=hello.txt — Download a file
- GET /api/files/list — List available files

## Tests

python -m pytest test_app.py -v
