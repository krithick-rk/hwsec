# Network Diagnostic Tool

A small Flask application that provides network diagnostic capabilities.

## Install

pip install -r requirements.txt

## Run

python app.py

Server starts on http://127.0.0.1:5001

## Endpoints

- POST /api/diagnostic/ping — Ping a host
  Body: {"host": "127.0.0.1"}
- GET  /api/diagnostic/health — Health check

## Tests

python -m pytest test_app.py -v
