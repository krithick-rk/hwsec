# Network Diagnostic Suite

A Flask application providing multiple network diagnostic tools through a
unified API. Tools include ping, traceroute, and DNS lookup.

## Install

pip install -r requirements.txt

## Run

python app.py

Server starts on http://127.0.0.1:5103

## Endpoints

- POST /api/diagnostic/run — Run a diagnostic tool
  Body: {"target": "127.0.0.1", "tool": "ping"}
- GET  /api/diagnostic/tools — List available tools

## Tests

python -m pytest test_app.py -v
