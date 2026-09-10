# Product Search Application

A small e-commerce search tool with web and API interfaces.

## Install

pip install -r requirements.txt

## Run

python app.py

Server starts on http://127.0.0.1:5101

## Endpoints

- GET /search?q=laptop — Web search page
- GET /api/search?q=mouse — JSON API search
- GET /api/products/1 — Get product by ID

## Tests

python -m pytest test_app.py -v
