# Layered File Service

A file management application with service, adapter, and utility layers.
Supports file download, preview, and listing.

## Architecture

app.py → FileService → StorageAdapter → PathUtils

## Install

pip install -r requirements.txt

## Run

python app.py

Server starts on http://127.0.0.1:5201

## Endpoints

- GET /api/files/download?filename=readme.txt — Download a file
- GET /api/files/preview?filename=readme.txt — Preview a file (first 500 chars)
- GET /api/files/list — List available files

## Tests

python -m pytest test_app.py -v
