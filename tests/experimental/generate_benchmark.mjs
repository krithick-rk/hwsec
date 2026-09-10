/**
 * Generator script for HWSEC Artificial Vulnerability Benchmark
 * Creates the complete benchmark directory structure, all 9 targets, 9 solutions, answer key, and scripts.
 */

import fs from 'fs';
import path from 'path';

const BENCH_ROOT = path.resolve('hwsec_artificial_benchmark');

function writeFile(relPath, content) {
    const fullPath = path.join(BENCH_ROOT, relPath);
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(fullPath, content.trim() + '\n', 'utf-8');
}

console.log(`[*] Generating HWSEC Artificial Vulnerability Benchmark at: ${BENCH_ROOT}`);

// ── Root README.md ───────────────────────────────────────────────────────────
writeFile('README.md', `# HWSEC Artificial Vulnerability Benchmark

A self-contained, reproducible set of intentionally vulnerable projects
for manual operational testing of the HWSEC security-operations framework.

## Structure

benchmark_targets/   — Vulnerable projects (HWSEC scans ONLY this directory)
solutions/            — Fixed versions of each project
answer_key/           — Manifest, expected findings, witness catalog
scripts/              — Validation and run-all scripts

## Quick Start

cd hwsec_artificial_benchmark
bash scripts/run_all_safe_checks.sh

## Difficulty Levels

- easy/   — Direct source-to-sink dataflow
- medium/ — Indirection through services/repositories
- hard/   — Multi-layer applications with false-positive traps

## Case Inventory

| Case ID    | Difficulty | Class               |
|------------|------------|---------------------|
| CASE-E01   | Easy       | OS Command Injection|
| CASE-E02   | Easy       | SQL Injection       |
| CASE-E03   | Easy       | Path Traversal      |
| CASE-M01   | Medium     | XSS                 |
| CASE-M02   | Medium     | SQL Injection       |
| CASE-M03   | Medium     | Command Injection   |
| CASE-H01   | Hard       | Path Traversal      |
| CASE-H02   | Hard       | LDAP Injection      |
| CASE-H03   | Hard       | XPath Injection     |

## Requirements

- Python 3.11+
- Linux (uses ping, touch, /tmp)
- See each case's requirements.txt
`);

// ── EASY CASES ───────────────────────────────────────────────────────────────

// CASE-E01
const E01_TARGET = 'benchmark_targets/easy/CASE-E01-command-injection';
writeFile(`${E01_TARGET}/app.py`, `from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)


@app.route('/api/diagnostic/ping', methods=['POST'])
def ping_host():
    host = request.json.get('host', '')
    if not host:
        return jsonify({'error': 'host parameter is required'}), 400

    command = f'ping -c 1 -W 2 {host}'
    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)

    return jsonify({
        'host': host,
        'output': result.stdout,
        'error': result.stderr,
        'returncode': result.returncode
    })


@app.route('/api/diagnostic/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)
`);
writeFile(`${E01_TARGET}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${E01_TARGET}/test_app.py`, `import os
import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_ping(client):
    response = client.post('/api/diagnostic/ping', json={'host': '127.0.0.1'})
    assert response.status_code == 200
    data = response.get_json()
    assert data['host'] == '127.0.0.1'


def test_missing_host(client):
    response = client.post('/api/diagnostic/ping', json={})
    assert response.status_code == 400


def test_special_input_handling(client):
    marker = '/tmp/hwsec_e01_marker'
    if os.path.exists(marker):
        os.remove(marker)

    response = client.post('/api/diagnostic/ping', json={'host': f'127.0.0.1; touch {marker}'})
    assert response.status_code == 200

    assert os.path.exists(marker), 'Expected marker file to be created'
    os.remove(marker)


def test_benign_no_side_effect(client):
    marker = '/tmp/hwsec_e01_marker'
    if os.path.exists(marker):
        os.remove(marker)

    response = client.post('/api/diagnostic/ping', json={'host': '127.0.0.1'})
    assert response.status_code == 200
    assert not os.path.exists(marker)


def test_health(client):
    response = client.get('/api/diagnostic/health')
    assert response.status_code == 200
`);
writeFile(`${E01_TARGET}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${E01_TARGET}/README.md`, `# Network Diagnostic Tool\n\nA small Flask application that provides network diagnostic capabilities.\n\n## Install\n\npip install -r requirements.txt\n\n## Run\n\npython app.py\n\nServer starts on http://127.0.0.1:5001\n\n## Endpoints\n\n- POST /api/diagnostic/ping — Ping a host\n  Body: {"host": "127.0.0.1"}\n- GET  /api/diagnostic/health — Health check\n\n## Tests\n\npython -m pytest test_app.py -v\n`);

// CASE-E01 FIXED
const E01_FIXED = 'solutions/easy/CASE-E01-command-injection-FIXED';
writeFile(`${E01_FIXED}/app.py`, `from flask import Flask, request, jsonify
import subprocess
import re

app = Flask(__name__)

HOST_PATTERN = re.compile(r'^[a-zA-Z0-9.\-]+$')


@app.route('/api/diagnostic/ping', methods=['POST'])
def ping_host():
    host = request.json.get('host', '')
    if not host:
        return jsonify({'error': 'host parameter is required'}), 400

    if not HOST_PATTERN.match(host) or len(host) > 255:
        return jsonify({'error': 'invalid host format'}), 400

    result = subprocess.run(
        ['ping', '-c', '1', '-W', '2', host],
        capture_output=True, text=True, timeout=10
    )

    return jsonify({
        'host': host,
        'output': result.stdout,
        'error': result.stderr,
        'returncode': result.returncode
    })


@app.route('/api/diagnostic/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)
`);
writeFile(`${E01_FIXED}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${E01_FIXED}/test_app.py`, `import os
import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_ping(client):
    response = client.post('/api/diagnostic/ping', json={'host': '127.0.0.1'})
    assert response.status_code == 200
    data = response.get_json()
    assert data['host'] == '127.0.0.1'


def test_regression_injection_blocked(client):
    marker = '/tmp/hwsec_e01_marker'
    if os.path.exists(marker):
        os.remove(marker)

    response = client.post('/api/diagnostic/ping', json={'host': f'127.0.0.1; touch {marker}'})
    assert response.status_code == 400
    assert not os.path.exists(marker), 'Marker file should not be created'


def test_benign_still_works(client):
    response = client.post('/api/diagnostic/ping', json={'host': '127.0.0.1'})
    assert response.status_code == 200


def test_health(client):
    response = client.get('/api/diagnostic/health')
    assert response.status_code == 200
`);
writeFile(`${E01_FIXED}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${E01_FIXED}/README.md`, `# Network Diagnostic Tool (Fixed)\n\nSame functionality as the original, with improved input validation.\n\n## Install & Run\n\npip install -r requirements.txt\npython app.py\n`);
writeFile(`${E01_FIXED}/FIX_NOTES.md`, `# Fix Notes — CASE-E01\n\n## Root Cause\nUser-controlled input was interpolated into a shell command string passed\nto subprocess.run with shell=True, allowing shell metacharacter injection.\n\n## Exact Remediation\n- Replaced shell=True with an argument list (shell=False)\n- Added input validation: host must match ^[a-zA-Z0-9.\\-]+$ and be <= 255 chars\n- The argument list form prevents shell interpretation of metacharacters\n\n## Why the Exploit No Longer Works\nThe input "127.0.0.1; touch /tmp/marker" fails validation (semicolon not\nin allowed character set) and even if it passed, the argument list form\npasses it as a single literal argument to ping, not to the shell.\n\n## Trade-offs\n- Hostnames with underscores are rejected (rare but valid)\n- IPv6 addresses not supported by the current regex (could be extended)\n`);

// CASE-E02
const E02_TARGET = 'benchmark_targets/easy/CASE-E02-sql-injection';
writeFile(`${E02_TARGET}/app.py`, `from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(':memory:')
    conn.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    )''')
    conn.executemany(
        'INSERT INTO users (id, username, email, role) VALUES (?, ?, ?, ?)',
        [
            (1, 'admin', 'admin@example.com', 'admin'),
            (2, 'alice', 'alice@example.com', 'user'),
            (3, 'bob', 'bob@example.com', 'user'),
            (4, 'charlie', 'charlie@example.com', 'user'),
        ]
    )
    conn.commit()
    return conn


db = get_db()


@app.route('/api/users/search', methods=['GET'])
def search_users():
    username = request.args.get('username', '')
    if not username:
        return jsonify({'error': 'username parameter is required'}), 400

    query = "SELECT id, username, email, role FROM users WHERE username = '" + username + "'"
    results = db.execute(query).fetchall()

    users = [{'id': r[0], 'username': r[1], 'email': r[2], 'role': r[3]} for r in results]
    return jsonify({'users': users, 'count': len(users)})


@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    result = db.execute('SELECT id, username, email, role FROM users WHERE id = ?', (user_id,)).fetchone()
    if result is None:
        return jsonify({'error': 'user not found'}), 404
    return jsonify({'id': result[0], 'username': result[1], 'email': result[2], 'role': result[3]})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5002, debug=True)
`);
writeFile(`${E02_TARGET}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${E02_TARGET}/test_app.py`, `import pytest
from app import app, db


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_search(client):
    response = client.get('/api/users/search?username=alice')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1
    assert data['users'][0]['username'] == 'alice'


def test_search_no_results(client):
    response = client.get('/api/users/search?username=nonexistent')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 0


def test_special_input_handling(client):
    response = client.get("/api/users/search?username=' OR '1'='1")
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] > 1, 'Expected multiple results from special input'


def test_benign_single_result(client):
    response = client.get('/api/users/search?username=admin')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1
    assert data['users'][0]['role'] == 'admin'
`);
writeFile(`${E02_TARGET}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${E02_TARGET}/README.md`, `# User Directory Service\n\nA small Flask application for searching user records.\n\n## Install\n\npip install -r requirements.txt\n\n## Run\n\npython app.py\n\nServer starts on http://127.0.0.1:5002\n\n## Endpoints\n\n- GET /api/users/search?username=alice — Search by username\n- GET /api/users/1 — Get user by ID\n\n## Tests\n\npython -m pytest test_app.py -v\n`);

// CASE-E02 FIXED
const E02_FIXED = 'solutions/easy/CASE-E02-sql-injection-FIXED';
writeFile(`${E02_FIXED}/app.py`, `from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(':memory:')
    conn.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    )''')
    conn.executemany(
        'INSERT INTO users (id, username, email, role) VALUES (?, ?, ?, ?)',
        [
            (1, 'admin', 'admin@example.com', 'admin'),
            (2, 'alice', 'alice@example.com', 'user'),
            (3, 'bob', 'bob@example.com', 'user'),
            (4, 'charlie', 'charlie@example.com', 'user'),
        ]
    )
    conn.commit()
    return conn


db = get_db()


@app.route('/api/users/search', methods=['GET'])
def search_users():
    username = request.args.get('username', '')
    if not username:
        return jsonify({'error': 'username parameter is required'}), 400

    query = 'SELECT id, username, email, role FROM users WHERE username = ?'
    results = db.execute(query, (username,)).fetchall()

    users = [{'id': r[0], 'username': r[1], 'email': r[2], 'role': r[3]} for r in results]
    return jsonify({'users': users, 'count': len(users)})


@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    result = db.execute('SELECT id, username, email, role FROM users WHERE id = ?', (user_id,)).fetchone()
    if result is None:
        return jsonify({'error': 'user not found'}), 404
    return jsonify({'id': result[0], 'username': result[1], 'email': result[2], 'role': result[3]})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5002, debug=True)
`);
writeFile(`${E02_FIXED}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${E02_FIXED}/test_app.py`, `import pytest
from app import app, db


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_search(client):
    response = client.get('/api/users/search?username=alice')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1
    assert data['users'][0]['username'] == 'alice'


def test_regression_injection_blocked(client):
    response = client.get("/api/users/search?username=' OR '1'='1")
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 0, 'Injection should return no results'


def test_benign_single_result(client):
    response = client.get('/api/users/search?username=admin')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1
`);
writeFile(`${E02_FIXED}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${E02_FIXED}/README.md`, `# User Directory Service (Fixed)\n\nSame functionality with parameterized queries.\n\n## Install & Run\n\npip install -r requirements.txt\npython app.py\n`);
writeFile(`${E02_FIXED}/FIX_NOTES.md`, `# Fix Notes — CASE-E02\n\n## Root Cause\nUser input was concatenated directly into an SQL query string,\nallowing SQL injection via crafted username parameters.\n\n## Exact Remediation\n- Replaced string concatenation with parameterized query using\n  placeholder (?) syntax\n- The database engine now treats the input as a literal value,\n  not as SQL syntax\n\n## Why the Exploit No Longer Works\nThe input "' OR '1'='1" is treated as a literal string value\nfor the username column comparison. No rows match this literal\nusername, so zero results are returned.\n\n## Trade-offs\nNone. Parameterized queries are the standard fix and preserve\nall normal functionality.\n`);

// CASE-E03
const E03_TARGET = 'benchmark_targets/easy/CASE-E03-path-traversal';
writeFile(`${E03_TARGET}/app.py`, `from flask import Flask, request, jsonify, send_file
import os

app = Flask(__name__)

FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')


@app.route('/api/files/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename', '')
    if not filename:
        return jsonify({'error': 'filename parameter is required'}), 400

    filepath = os.path.join(FILES_DIR, filename)

    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return jsonify({'filename': filename, 'content': content})
    except FileNotFoundError:
        return jsonify({'error': 'file not found'}), 404
    except IsADirectoryError:
        return jsonify({'error': 'path is a directory'}), 400


@app.route('/api/files/list', methods=['GET'])
def list_files():
    files = os.listdir(FILES_DIR)
    return jsonify({'files': files})


if __name__ == '__main__':
    os.makedirs(FILES_DIR, exist_ok=True)
    for name, content in [('hello.txt', 'Hello World!\\n'), ('info.txt', 'Sample info file.\\n')]:
        with open(os.path.join(FILES_DIR, name), 'w') as f:
            f.write(content)
    app.run(host='127.0.0.1', port=5003, debug=True)
`);
writeFile(`${E03_TARGET}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${E03_TARGET}/test_app.py`, `import os
import pytest
from app import app, FILES_DIR


@pytest.fixture
def client():
    os.makedirs(FILES_DIR, exist_ok=True)
    for name, content in [('hello.txt', 'Hello World!\\n'), ('info.txt', 'Sample info file.\\n')]:
        with open(os.path.join(FILES_DIR, name), 'w') as f:
            f.write(content)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_download(client):
    response = client.get('/api/files/download?filename=hello.txt')
    assert response.status_code == 200
    data = response.get_json()
    assert 'Hello World' in data['content']


def test_list_files(client):
    response = client.get('/api/files/list')
    assert response.status_code == 200
    data = response.get_json()
    assert 'hello.txt' in data['files']


def test_special_input_handling(client):
    response = client.get('/api/files/download?filename=../../../../etc/hostname')
    assert response.status_code == 200
    data = response.get_json()
    assert data['content'] != '', 'Expected file content from special path'


def test_benign_no_traversal(client):
    response = client.get('/api/files/download?filename=hello.txt')
    assert response.status_code == 200
    data = response.get_json()
    assert data['content'] == 'Hello World!\\n'
`);
writeFile(`${E03_TARGET}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${E03_TARGET}/README.md`, `# File Download Service\n\nA small Flask application for serving files from a local directory.\n\n## Install\n\npip install -r requirements.txt\n\n## Run\n\npython app.py\n\nServer starts on http://127.0.0.1:5003\n\n## Endpoints\n\n- GET /api/files/download?filename=hello.txt — Download a file\n- GET /api/files/list — List available files\n\n## Tests\n\npython -m pytest test_app.py -v\n`);

// CASE-E03 FIXED
const E03_FIXED = 'solutions/easy/CASE-E03-path-traversal-FIXED';
writeFile(`${E03_FIXED}/app.py`, `from flask import Flask, request, jsonify
import os

app = Flask(__name__)

FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')


def safe_resolve_path(base_dir, filename):
    base_real = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base_dir, filename))
    if not target.startswith(base_real + os.sep) and target != base_real:
        return None
    return target


@app.route('/api/files/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename', '')
    if not filename:
        return jsonify({'error': 'filename parameter is required'}), 400

    filepath = safe_resolve_path(FILES_DIR, filename)
    if filepath is None:
        return jsonify({'error': 'access denied'}), 403

    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return jsonify({'filename': os.path.basename(filepath), 'content': content})
    except FileNotFoundError:
        return jsonify({'error': 'file not found'}), 404
    except IsADirectoryError:
        return jsonify({'error': 'path is a directory'}), 400


@app.route('/api/files/list', methods=['GET'])
def list_files():
    files = os.listdir(FILES_DIR)
    return jsonify({'files': files})


if __name__ == '__main__':
    os.makedirs(FILES_DIR, exist_ok=True)
    for name, content in [('hello.txt', 'Hello World!\\n'), ('info.txt', 'Sample info file.\\n')]:
        with open(os.path.join(FILES_DIR, name), 'w') as f:
            f.write(content)
    app.run(host='127.0.0.1', port=5003, debug=True)
`);
writeFile(`${E03_FIXED}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${E03_FIXED}/test_app.py`, `import os
import pytest
from app import app, FILES_DIR


@pytest.fixture
def client():
    os.makedirs(FILES_DIR, exist_ok=True)
    for name, content in [('hello.txt', 'Hello World!\\n'), ('info.txt', 'Sample info file.\\n')]:
        with open(os.path.join(FILES_DIR, name), 'w') as f:
            f.write(content)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_download(client):
    response = client.get('/api/files/download?filename=hello.txt')
    assert response.status_code == 200
    data = response.get_json()
    assert 'Hello World' in data['content']


def test_regression_traversal_blocked(client):
    response = client.get('/api/files/download?filename=../../../../etc/hostname')
    assert response.status_code == 403


def test_benign_still_works(client):
    response = client.get('/api/files/download?filename=info.txt')
    assert response.status_code == 200
    data = response.get_json()
    assert 'Sample info' in data['content']
`);
writeFile(`${E03_FIXED}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${E03_FIXED}/README.md`, `# File Download Service (Fixed)\n\nSame functionality with path validation.\n\n## Install & Run\n\npip install -r requirements.txt\npython app.py\n`);
writeFile(`${E03_FIXED}/FIX_NOTES.md`, `# Fix Notes — CASE-E03\n\n## Root Cause\nUser-controlled filename was joined with the base directory path using\nos.path.join without verifying the resolved path stays within the base\ndirectory, allowing path traversal via ../ sequences.\n\n## Exact Remediation\n- Added safe_resolve_path() that uses os.path.realpath to resolve\n  the full path and then verifies it starts with the base directory\n- If the resolved path escapes the base directory, the request is\n  rejected with 403 Forbidden\n- Uses os.path.realpath to handle symlinks and ../ sequences\n\n## Why the Exploit No Longer Works\nThe input "../../../../etc/hostname" resolves to a path outside the\nFILES_DIR, which is detected by the prefix check, resulting in a 403.\n\n## Trade-offs\n- realpath resolves symlinks, which could reject legitimate symlinks\n  inside the files directory (acceptable for a file download service)\n`);

// ── MEDIUM CASES ─────────────────────────────────────────────────────────────

// CASE-M01
const M01_TARGET = 'benchmark_targets/medium/CASE-M01-xss-reflection';
writeFile(`${M01_TARGET}/app.py`, `from flask import Flask, request, render_template, jsonify
from services.search_service import SearchService

app = Flask(__name__)
app.template_folder = 'templates'

search_service = SearchService()


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    results = search_service.search_products(query)
    return render_template('search.html', query=query, results=results)


@app.route('/api/search', methods=['GET'])
def api_search():
    query = request.args.get('q', '')
    results = search_service.search_products(query)
    return jsonify({'query': query, 'results': results, 'count': len(results)})


@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = search_service.get_product(product_id)
    if product is None:
        return jsonify({'error': 'product not found'}), 404
    return jsonify(product)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5101, debug=True)
`);
writeFile(`${M01_TARGET}/services/__init__.py`, '');
writeFile(`${M01_TARGET}/services/search_service.py`, `import html


class SearchService:
    def __init__(self):
        self._products = [
            {'id': 1, 'name': 'Laptop Pro', 'price': 1299.99, 'category': 'electronics'},
            {'id': 2, 'name': 'Wireless Mouse', 'price': 29.99, 'category': 'electronics'},
            {'id': 3, 'name': 'Coffee Mug', 'price': 12.50, 'category': 'kitchen'},
            {'id': 4, 'name': 'Notebook', 'price': 4.99, 'category': 'office'},
            {'id': 5, 'name': 'Desk Lamp', 'price': 45.00, 'category': 'office'},
        ]

    def _sanitize(self, text):
        cleaned = text.replace('<script>', '').replace('</script>', '')
        cleaned = cleaned.replace('<SCRIPT>', '').replace('</SCRIPT>', '')
        return cleaned

    def search_products(self, query):
        sanitized = self._sanitize(query)
        if not sanitized:
            return self._products[:5]
        lowered = sanitized.lower()
        return [p for p in self._products if lowered in p['name'].lower()]

    def get_product(self, product_id):
        for p in self._products:
            if p['id'] == product_id:
                return p
        return None
`);
writeFile(`${M01_TARGET}/templates/search.html`, `<!DOCTYPE html>
<html>
<head><title>Product Search</title></head>
<body>
    <h1>Product Search</h1>
    <form method="GET" action="/search">
        <input type="text" name="q" value="{{ query }}" placeholder="Search products...">
        <button type="submit">Search</button>
    </form>
    <div id="results">
        <p>You searched for: <span id="query-display">{{ query | safe }}</span></p>
        {% if results %}
        <ul>
        {% for product in results %}
            <li>{{ product.name }} - \${{ "%.2f"|format(product.price) }}</li>
        {% endfor %}
        </ul>
        {% else %}
        <p>No products found.</p>
        {% endif %}
    </div>
</body>
</html>
`);
writeFile(`${M01_TARGET}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${M01_TARGET}/test_app.py`, `import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_search(client):
    response = client.get('/search?q=laptop')
    assert response.status_code == 200
    assert b'Laptop Pro' in response.data


def test_api_search(client):
    response = client.get('/api/search?q=mouse')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1


def test_special_input_handling(client):
    payload = '<img src=x onerror=alert(1)>'
    response = client.get(f'/search?q={payload}')
    assert response.status_code == 200
    raw = response.data.decode('utf-8')
    assert payload in raw, 'Expected unescaped content in response'


def test_benign_search_no_html(client):
    response = client.get('/search?q=coffee')
    assert response.status_code == 200
    assert b'<img' not in response.data


def test_product_by_id(client):
    response = client.get('/api/products/1')
    assert response.status_code == 200
    data = response.get_json()
    assert data['name'] == 'Laptop Pro'
`);
writeFile(`${M01_TARGET}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${M01_TARGET}/README.md`, `# Product Search Application\n\nA small e-commerce search tool with web and API interfaces.\n\n## Install\n\npip install -r requirements.txt\n\n## Run\n\npython app.py\n\nServer starts on http://127.0.0.1:5101\n\n## Endpoints\n\n- GET /search?q=laptop — Web search page\n- GET /api/search?q=mouse — JSON API search\n- GET /api/products/1 — Get product by ID\n\n## Tests\n\npython -m pytest test_app.py -v\n`);

// CASE-M01 FIXED
const M01_FIXED = 'solutions/medium/CASE-M01-xss-reflection-FIXED';
writeFile(`${M01_FIXED}/app.py`, `from flask import Flask, request, render_template, jsonify
from services.search_service import SearchService

app = Flask(__name__)
app.template_folder = 'templates'

search_service = SearchService()


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    results = search_service.search_products(query)
    return render_template('search.html', query=query, results=results)


@app.route('/api/search', methods=['GET'])
def api_search():
    query = request.args.get('q', '')
    results = search_service.search_products(query)
    return jsonify({'query': query, 'results': results, 'count': len(results)})


@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = search_service.get_product(product_id)
    if product is None:
        return jsonify({'error': 'product not found'}), 404
    return jsonify(product)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5101, debug=True)
`);
writeFile(`${M01_FIXED}/services/__init__.py`, '');
writeFile(`${M01_FIXED}/services/search_service.py`, `class SearchService:
    def __init__(self):
        self._products = [
            {'id': 1, 'name': 'Laptop Pro', 'price': 1299.99, 'category': 'electronics'},
            {'id': 2, 'name': 'Wireless Mouse', 'price': 29.99, 'category': 'electronics'},
            {'id': 3, 'name': 'Coffee Mug', 'price': 12.50, 'category': 'kitchen'},
            {'id': 4, 'name': 'Notebook', 'price': 4.99, 'category': 'office'},
            {'id': 5, 'name': 'Desk Lamp', 'price': 45.00, 'category': 'office'},
        ]

    def search_products(self, query):
        if not query:
            return self._products[:5]
        lowered = query.lower()
        return [p for p in self._products if lowered in p['name'].lower()]

    def get_product(self, product_id):
        for p in self._products:
            if p['id'] == product_id:
                return p
        return None
`);
writeFile(`${M01_FIXED}/templates/search.html`, `<!DOCTYPE html>
<html>
<head><title>Product Search</title></head>
<body>
    <h1>Product Search</h1>
    <form method="GET" action="/search">
        <input type="text" name="q" value="{{ query }}" placeholder="Search products...">
        <button type="submit">Search</button>
    </form>
    <div id="results">
        <p>You searched for: <span id="query-display">{{ query }}</span></p>
        {% if results %}
        <ul>
        {% for product in results %}
            <li>{{ product.name }} - \${{ "%.2f"|format(product.price) }}</li>
        {% endfor %}
        </ul>
        {% else %}
        <p>No products found.</p>
        {% endif %}
    </div>
</body>
</html>
`);
writeFile(`${M01_FIXED}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${M01_FIXED}/test_app.py`, `import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_search(client):
    response = client.get('/search?q=laptop')
    assert response.status_code == 200
    assert b'Laptop Pro' in response.data


def test_regression_xss_blocked(client):
    payload = '<img src=x onerror=alert(1)>'
    response = client.get(f'/search?q={payload}')
    assert response.status_code == 200
    raw = response.data.decode('utf-8')
    assert payload not in raw, 'Input should be escaped'


def test_benign_still_works(client):
    response = client.get('/search?q=coffee')
    assert response.status_code == 200
    assert b'Coffee Mug' in response.data
`);
writeFile(`${M01_FIXED}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${M01_FIXED}/README.md`, `# Product Search Application (Fixed)\n\nSame functionality with proper output escaping.\n\n## Install & Run\n\npip install -r requirements.txt\npython app.py\n`);
writeFile(`${M01_FIXED}/FIX_NOTES.md`, `# Fix Notes — CASE-M01\n\n## Root Cause\nThe template used the Jinja2 \`| safe\` filter to render user input\nwithout escaping, combined with an incomplete sanitizer that only\nstripped <script> tags but not other HTML event handlers.\n\n## Exact Remediation\n- Removed the \`| safe\` filter from the template, allowing Jinja2's\n  default auto-escaping to handle all user input\n- Removed the incomplete _sanitize() method from SearchService since\n  Jinja2 auto-escaping provides complete protection\n- The query is now rendered as escaped text, not raw HTML\n\n## Why the Exploit No Longer Works\nThe payload \`<img src=x onerror=alert(1)>\` is rendered as escaped\nHTML entities: \`&lt;img src=x onerror=alert(1)&gt;\`, which the browser\ndisplays as text rather than executing as HTML.\n\n## Trade-offs\n- Users can no longer legitimately include HTML in search queries\n  (acceptable for a search interface)\n`);

// CASE-M02
const M02_TARGET = 'benchmark_targets/medium/CASE-M02-sql-injection-indirect';
writeFile(`${M02_TARGET}/app.py`, `from flask import Flask, request, jsonify
from services.user_service import UserService
from database import init_db

app = Flask(__name__)

db = init_db()
user_service = UserService(db)


@app.route('/api/users/search', methods=['GET'])
def search_users():
    pattern = request.args.get('pattern', '')
    if not pattern:
        return jsonify({'error': 'pattern parameter is required'}), 400
    users = user_service.find_users_by_pattern(pattern)
    return jsonify({'users': users, 'count': len(users)})


@app.route('/api/users/by_role/<role>', methods=['GET'])
def get_users_by_role(role):
    users = user_service.find_users_by_role(role)
    return jsonify({'users': users, 'count': len(users)})


@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = user_service.get_user_by_id(user_id)
    if user is None:
        return jsonify({'error': 'user not found'}), 404
    return jsonify(user)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5102, debug=True)
`);
writeFile(`${M02_TARGET}/database.py`, `import sqlite3


def init_db():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        department TEXT
    )''')
    conn.executemany(
        'INSERT INTO users (id, username, email, role, department) VALUES (?, ?, ?, ?, ?)',
        [
            (1, 'admin', 'admin@example.com', 'admin', 'IT'),
            (2, 'alice', 'alice@example.com', 'user', 'Engineering'),
            (3, 'bob', 'bob@example.com', 'user', 'Marketing'),
            (4, 'charlie', 'charlie@example.com', 'manager', 'Engineering'),
            (5, 'diana', 'diana@example.com', 'user', 'Sales'),
        ]
    )
    conn.commit()
    return conn
`);
writeFile(`${M02_TARGET}/services/__init__.py`, '');
writeFile(`${M02_TARGET}/services/user_service.py`, `from repositories.user_repository import UserRepository


class UserService:
    def __init__(self, db):
        self.repository = UserRepository(db)

    def find_users_by_pattern(self, pattern):
        search_term = '%' + pattern + '%'
        return self.repository.search_users(search_term)

    def find_users_by_role(self, role):
        return self.repository.get_users_by_role(role)

    def get_user_by_id(self, user_id):
        return self.repository.get_by_id(user_id)
`);
writeFile(`${M02_TARGET}/repositories/__init__.py`, '');
writeFile(`${M02_TARGET}/repositories/user_repository.py`, `class UserRepository:
    def __init__(self, db):
        self.db = db

    def search_users(self, search_term):
        query = "SELECT id, username, email, role, department FROM users WHERE username LIKE '" + search_term + "'"
        rows = self.db.execute(query).fetchall()
        return [dict(row) for row in rows]

    def get_users_by_role(self, role):
        rows = self.db.execute(
            'SELECT id, username, email, role, department FROM users WHERE role = ?',
            (role,)
        ).fetchall()
        return [dict(row) for row in rows]

    def get_by_id(self, user_id):
        row = self.db.execute(
            'SELECT id, username, email, role, department FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()
        return dict(row) if row else None
`);
writeFile(`${M02_TARGET}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${M02_TARGET}/test_app.py`, `import pytest
from app import app, db


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_search(client):
    response = client.get('/api/users/search?pattern=ali')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1
    assert data['users'][0]['username'] == 'alice'


def test_search_by_role(client):
    response = client.get('/api/users/by_role/user')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 3


def test_special_input_handling(client):
    response = client.get("/api/users/search?pattern=' UNION SELECT id, username, email, role, department FROM users-- ")
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] > 1, 'Expected multiple results from special input'


def test_benign_single_result(client):
    response = client.get('/api/users/search?pattern=admin')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1


def test_get_user_by_id(client):
    response = client.get('/api/users/1')
    assert response.status_code == 200
    data = response.get_json()
    assert data['username'] == 'admin'
`);
writeFile(`${M02_TARGET}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${M02_TARGET}/README.md`, `# User Management Service\n\nA Flask application with service/repository layers for managing user records.\n\n## Install\n\npip install -r requirements.txt\n\n## Run\n\npython app.py\n\nServer starts on http://127.0.0.1:5102\n\n## Endpoints\n\n- GET /api/users/search?pattern=ali — Search by username pattern\n- GET /api/users/by_role/user — Filter by role\n- GET /api/users/1 — Get user by ID\n\n## Tests\n\npython -m pytest test_app.py -v\n`);

// CASE-M02 FIXED
const M02_FIXED = 'solutions/medium/CASE-M02-sql-injection-indirect-FIXED';
writeFile(`${M02_FIXED}/app.py`, `from flask import Flask, request, jsonify
from services.user_service import UserService
from database import init_db

app = Flask(__name__)

db = init_db()
user_service = UserService(db)


@app.route('/api/users/search', methods=['GET'])
def search_users():
    pattern = request.args.get('pattern', '')
    if not pattern:
        return jsonify({'error': 'pattern parameter is required'}), 400
    users = user_service.find_users_by_pattern(pattern)
    return jsonify({'users': users, 'count': len(users)})


@app.route('/api/users/by_role/<role>', methods=['GET'])
def get_users_by_role(role):
    users = user_service.find_users_by_role(role)
    return jsonify({'users': users, 'count': len(users)})


@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = user_service.get_user_by_id(user_id)
    if user is None:
        return jsonify({'error': 'user not found'}), 404
    return jsonify(user)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5102, debug=True)
`);
writeFile(`${M02_FIXED}/database.py`, `import sqlite3


def init_db():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        department TEXT
    )''')
    conn.executemany(
        'INSERT INTO users (id, username, email, role, department) VALUES (?, ?, ?, ?, ?)',
        [
            (1, 'admin', 'admin@example.com', 'admin', 'IT'),
            (2, 'alice', 'alice@example.com', 'user', 'Engineering'),
            (3, 'bob', 'bob@example.com', 'user', 'Marketing'),
            (4, 'charlie', 'charlie@example.com', 'manager', 'Engineering'),
            (5, 'diana', 'diana@example.com', 'user', 'Sales'),
        ]
    )
    conn.commit()
    return conn
`);
writeFile(`${M02_FIXED}/services/__init__.py`, '');
writeFile(`${M02_FIXED}/services/user_service.py`, `from repositories.user_repository import UserRepository


class UserService:
    def __init__(self, db):
        self.repository = UserRepository(db)

    def find_users_by_pattern(self, pattern):
        return self.repository.search_users(pattern)

    def find_users_by_role(self, role):
        return self.repository.get_users_by_role(role)

    def get_user_by_id(self, user_id):
        return self.repository.get_by_id(user_id)
`);
writeFile(`${M02_FIXED}/repositories/__init__.py`, '');
writeFile(`${M02_FIXED}/repositories/user_repository.py`, `class UserRepository:
    def __init__(self, db):
        self.db = db

    def search_users(self, search_term):
        rows = self.db.execute(
            'SELECT id, username, email, role, department FROM users WHERE username LIKE ?',
            ('%' + search_term + '%',)
        ).fetchall()
        return [dict(row) for row in rows]

    def get_users_by_role(self, role):
        rows = self.db.execute(
            'SELECT id, username, email, role, department FROM users WHERE role = ?',
            (role,)
        ).fetchall()
        return [dict(row) for row in rows]

    def get_by_id(self, user_id):
        row = self.db.execute(
            'SELECT id, username, email, role, department FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()
        return dict(row) if row else None
`);
writeFile(`${M02_FIXED}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${M02_FIXED}/test_app.py`, `import pytest
from app import app, db


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_search(client):
    response = client.get('/api/users/search?pattern=ali')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1


def test_regression_injection_blocked(client):
    response = client.get("/api/users/search?pattern=' UNION SELECT id, username, email, role, department FROM users-- ")
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 0


def test_benign_still_works(client):
    response = client.get('/api/users/search?pattern=admin')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1
`);
writeFile(`${M02_FIXED}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${M02_FIXED}/README.md`, `# User Management Service (Fixed)\n\nSame functionality with parameterized queries throughout.\n\n## Install & Run\n\npip install -r requirements.txt\npython app.py\n`);
writeFile(`${M02_FIXED}/FIX_NOTES.md`, `# Fix Notes — CASE-M02\n\n## Root Cause\nThe UserRepository.search_users() method concatenated user input\n(transformed by UserService) directly into an SQL LIKE query string.\nThe UserService added '%' wildcards but did not prevent SQL injection,\nand the repository used string concatenation instead of parameterization.\n\n## Exact Remediation\n- Changed UserRepository.search_users() to use a parameterized query\n  with the LIKE operator and a ? placeholder\n- Removed the string concatenation in the repository\n- The LIKE wildcards (%) are now part of the parameter value, not the\n  SQL string, so they cannot alter query structure\n\n## Why the Exploit No Longer Works\nThe UNION SELECT injection payload is treated as a literal search string.\nNo users match the literal string "' UNION SELECT ...", so zero results\nare returned.\n\n## Trade-offs\n- The LIKE operator with parameterized input may perform differently\n  if the input contains % characters, but this is standard behavior\n`);

// CASE-M03
const M03_TARGET = 'benchmark_targets/medium/CASE-M03-command-injection-conditional';
writeFile(`${M03_TARGET}/app.py`, `from flask import Flask, request, jsonify
from services.diagnostic_service import DiagnosticService

app = Flask(__name__)
diag_service = DiagnosticService()


@app.route('/api/diagnostic/run', methods=['POST'])
def run_diagnostic():
    data = request.json or {}
    target = data.get('target', '')
    tool = data.get('tool', 'ping')

    if not target:
        return jsonify({'error': 'target parameter is required'}), 400

    result = diag_service.run_tool(target, tool)
    return jsonify(result)


@app.route('/api/diagnostic/tools', methods=['GET'])
def list_tools():
    return jsonify({'tools': diag_service.available_tools()})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5103, debug=True)
`);
writeFile(`${M03_TARGET}/services/__init__.py`, '');
writeFile(`${M03_TARGET}/services/diagnostic_service.py`, `import subprocess


class DiagnosticService:
    TOOLS = {
        'ping': 'Network connectivity check (ICMP)',
        'traceroute': 'Network path tracing',
        'dns_lookup': 'DNS resolution check',
    }

    def available_tools(self):
        return [{'name': k, 'description': v} for k, v in self.TOOLS.items()]

    def run_tool(self, target, tool):
        if tool == 'ping':
            return self._run_ping(target)
        elif tool == 'traceroute':
            return self._run_traceroute(target)
        elif tool == 'dns_lookup':
            return self._run_dns_lookup(target)
        else:
            return {'error': f'unknown tool: {tool}', 'available': list(self.TOOLS.keys())}

    def _run_ping(self, target):
        command = f'ping -c 1 -W 2 {target}'
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        return {
            'tool': 'ping',
            'target': target,
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        }

    def _run_traceroute(self, target):
        result = subprocess.run(
            ['traceroute', '-m', '5', target],
            capture_output=True, text=True, timeout=15
        )
        return {
            'tool': 'traceroute',
            'target': target,
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        }

    def _run_dns_lookup(self, target):
        result = subprocess.run(
            ['nslookup', target],
            capture_output=True, text=True, timeout=10
        )
        return {
            'tool': 'dns_lookup',
            'target': target,
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        }
`);
writeFile(`${M03_TARGET}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${M03_TARGET}/test_app.py`, `import os
import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_ping(client):
    response = client.post('/api/diagnostic/run', json={'target': '127.0.0.1', 'tool': 'ping'})
    assert response.status_code == 200
    data = response.get_json()
    assert data['tool'] == 'ping'


def test_list_tools(client):
    response = client.get('/api/diagnostic/tools')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['tools']) == 3


def test_special_input_ping(client):
    marker = '/tmp/hwsec_m03_marker'
    if os.path.exists(marker):
        os.remove(marker)

    response = client.post('/api/diagnostic/run', json={
        'target': f'127.0.0.1; touch {marker}',
        'tool': 'ping'
    })
    assert response.status_code == 200
    assert os.path.exists(marker), 'Expected marker file from ping tool'
    os.remove(marker)


def test_traceroute_no_side_effect(client):
    marker = '/tmp/hwsec_m03_marker'
    if os.path.exists(marker):
        os.remove(marker)

    response = client.post('/api/diagnostic/run', json={
        'target': f'127.0.0.1; touch {marker}',
        'tool': 'traceroute'
    })
    assert response.status_code == 200
    assert not os.path.exists(marker), 'Traceroute should not create marker'


def test_unknown_tool(client):
    response = client.post('/api/diagnostic/run', json={'target': '127.0.0.1', 'tool': 'nmap'})
    assert response.status_code == 200
    data = response.get_json()
    assert 'error' in data
`);
writeFile(`${M03_TARGET}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${M03_TARGET}/README.md`, `# Network Diagnostic Suite\n\nA Flask application providing multiple network diagnostic tools through a\nunified API. Tools include ping, traceroute, and DNS lookup.\n\n## Install\n\npip install -r requirements.txt\n\n## Run\n\npython app.py\n\nServer starts on http://127.0.0.1:5103\n\n## Endpoints\n\n- POST /api/diagnostic/run — Run a diagnostic tool\n  Body: {"target": "127.0.0.1", "tool": "ping"}\n- GET  /api/diagnostic/tools — List available tools\n\n## Tests\n\npython -m pytest test_app.py -v\n`);

// CASE-M03 FIXED
const M03_FIXED = 'solutions/medium/CASE-M03-command-injection-conditional-FIXED';
writeFile(`${M03_FIXED}/app.py`, `from flask import Flask, request, jsonify
from services.diagnostic_service import DiagnosticService

app = Flask(__name__)
diag_service = DiagnosticService()


@app.route('/api/diagnostic/run', methods=['POST'])
def run_diagnostic():
    data = request.json or {}
    target = data.get('target', '')
    tool = data.get('tool', 'ping')

    if not target:
        return jsonify({'error': 'target parameter is required'}), 400

    result = diag_service.run_tool(target, tool)
    if 'error' in result and 'tool' not in result:
        return jsonify(result), 400
    return jsonify(result)


@app.route('/api/diagnostic/tools', methods=['GET'])
def list_tools():
    return jsonify({'tools': diag_service.available_tools()})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5103, debug=True)
`);
writeFile(`${M03_FIXED}/services/__init__.py`, '');
writeFile(`${M03_FIXED}/services/diagnostic_service.py`, `import subprocess
import re

TARGET_PATTERN = re.compile(r'^[a-zA-Z0-9.\-]+$')


class DiagnosticService:
    TOOLS = {
        'ping': 'Network connectivity check (ICMP)',
        'traceroute': 'Network path tracing',
        'dns_lookup': 'DNS resolution check',
    }

    def available_tools(self):
        return [{'name': k, 'description': v} for k, v in self.TOOLS.items()]

    def run_tool(self, target, tool):
        if not TARGET_PATTERN.match(target) or len(target) > 255:
            return {'error': 'invalid target format'}

        if tool == 'ping':
            return self._run_ping(target)
        elif tool == 'traceroute':
            return self._run_traceroute(target)
        elif tool == 'dns_lookup':
            return self._run_dns_lookup(target)
        else:
            return {'error': f'unknown tool: {tool}', 'available': list(self.TOOLS.keys())}

    def _run_ping(self, target):
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '2', target],
            capture_output=True, text=True, timeout=10
        )
        return {
            'tool': 'ping',
            'target': target,
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        }

    def _run_traceroute(self, target):
        result = subprocess.run(
            ['traceroute', '-m', '5', target],
            capture_output=True, text=True, timeout=15
        )
        return {
            'tool': 'traceroute',
            'target': target,
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        }

    def _run_dns_lookup(self, target):
        result = subprocess.run(
            ['nslookup', target],
            capture_output=True, text=True, timeout=10
        )
        return {
            'tool': 'dns_lookup',
            'target': target,
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        }
`);
writeFile(`${M03_FIXED}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${M03_FIXED}/test_app.py`, `import os
import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_ping(client):
    response = client.post('/api/diagnostic/run', json={'target': '127.0.0.1', 'tool': 'ping'})
    assert response.status_code == 200


def test_regression_injection_blocked(client):
    marker = '/tmp/hwsec_m03_marker'
    if os.path.exists(marker):
        os.remove(marker)

    response = client.post('/api/diagnostic/run', json={
        'target': f'127.0.0.1; touch {marker}',
        'tool': 'ping'
    })
    assert response.status_code == 400
    assert not os.path.exists(marker)


def test_benign_still_works(client):
    response = client.post('/api/diagnostic/run', json={'target': '127.0.0.1', 'tool': 'ping'})
    assert response.status_code == 200
`);
writeFile(`${M03_FIXED}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${M03_FIXED}/README.md`, `# Network Diagnostic Suite (Fixed)\n\nSame functionality with input validation and safe subprocess calls.\n\n## Install & Run\n\npip install -r requirements.txt\npython app.py\n`);
writeFile(`${M03_FIXED}/FIX_NOTES.md`, `# Fix Notes — CASE-M03\n\n## Root Cause\nThe _run_ping() method used shell=True with a string-interpolated\ncommand, while _run_traceroute() and _run_dns_lookup() used argument\nlists. The vulnerability was conditional on selecting the 'ping' tool.\n\n## Exact Remediation\n- Changed _run_ping() to use subprocess.run with an argument list\n  (shell=False), matching the pattern already used by traceroute\n- Added input validation (regex + length check) at the service level\n  for all tools, rejecting input with shell metacharacters\n\n## Why the Exploit No Longer Works\nThe input "127.0.0.1; touch /tmp/marker" fails the regex validation\n(semicolon not allowed), so the diagnostic is never executed. Even if\nvalidation were bypassed, the argument list form prevents shell\ninterpretation.\n\n## Trade-offs\n- Hostnames with underscores are rejected (rare but valid)\n`);

// ── HARD CASES ───────────────────────────────────────────────────────────────

// CASE-H01
const H01_TARGET = 'benchmark_targets/hard/CASE-H01-path-traversal-layered';
writeFile(`${H01_TARGET}/app.py`, `from flask import Flask, request, jsonify
from services.file_service import FileService
from config import Config

app = Flask(__name__)
config = Config()
file_service = FileService(config)


@app.route('/api/files/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename', '')
    if not filename:
        return jsonify({'error': 'filename parameter is required'}), 400
    result = file_service.read_file(filename)
    if result is None:
        return jsonify({'error': 'file not found'}), 404
    if isinstance(result, dict) and 'error' in result:
        return jsonify(result), 403
    return jsonify({'filename': filename, 'content': result})


@app.route('/api/files/preview', methods=['GET'])
def preview_file():
    filename = request.args.get('filename', '')
    if not filename:
        return jsonify({'error': 'filename parameter is required'}), 400
    result = file_service.preview_file(filename)
    if result is None:
        return jsonify({'error': 'file not found'}), 404
    if isinstance(result, dict) and 'error' in result:
        return jsonify(result), 403
    return jsonify({'filename': filename, 'content': result, 'preview': True})


@app.route('/api/files/list', methods=['GET'])
def list_files():
    files = file_service.list_files()
    return jsonify({'files': files})


if __name__ == '__main__':
    file_service.init_storage()
    app.run(host='127.0.0.1', port=5201, debug=True)
`);
writeFile(`${H01_TARGET}/config.py`, `import os


class Config:
    BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'storage')

    def get_base_dir(self):
        return self.BASE_DIR
`);
writeFile(`${H01_TARGET}/services/__init__.py`, '');
writeFile(`${H01_TARGET}/services/file_service.py`, `from adapters.storage_adapter import StorageAdapter


class FileService:
    def __init__(self, config):
        self.config = config
        self.adapter = StorageAdapter(config)

    def read_file(self, filename):
        return self.adapter.read(filename)

    def preview_file(self, filename):
        content = self.adapter.read_preview(filename)
        if content is None:
            return None
        if isinstance(content, str):
            return content[:500]
        return content

    def list_files(self):
        return self.adapter.list_files()

    def init_storage(self):
        self.adapter.init_storage()
`);
writeFile(`${H01_TARGET}/adapters/__init__.py`, '');
writeFile(`${H01_TARGET}/adapters/storage_adapter.py`, `import os
from utils.path_utils import PathUtils


class StorageAdapter:
    def __init__(self, config):
        self.config = config
        self.base_dir = config.get_base_dir()
        self.path_utils = PathUtils()

    def read(self, filename):
        filepath = self.path_utils.join_path(self.base_dir, filename)
        if filepath is None:
            return {'error': 'invalid path'}
        try:
            with open(filepath, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return None
        except IsADirectoryError:
            return {'error': 'path is a directory'}

    def read_preview(self, filename):
        filepath = self.path_utils.join_path_safe(self.base_dir, filename)
        if filepath is None:
            return {'error': 'invalid path'}
        try:
            with open(filepath, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return None
        except IsADirectoryError:
            return {'error': 'path is a directory'}

    def list_files(self):
        if not os.path.exists(self.base_dir):
            return []
        return os.listdir(self.base_dir)

    def init_storage(self):
        os.makedirs(self.base_dir, exist_ok=True)
        for name, content in [('readme.txt', 'Welcome to the file service.\\n'),
                              ('notes.txt', 'Some important notes.\\n'),
                              ('config.txt', 'default configuration\\n')]:
            path = os.path.join(self.base_dir, name)
            with open(path, 'w') as f:
                f.write(content)
`);
writeFile(`${H01_TARGET}/utils/__init__.py`, '');
writeFile(`${H01_TARGET}/utils/path_utils.py`, `import os


class PathUtils:
    def join_path(self, base_dir, filename):
        return os.path.join(base_dir, filename)

    def join_path_safe(self, base_dir, filename):
        base_real = os.path.realpath(base_dir)
        target = os.path.realpath(os.path.join(base_dir, filename))
        if not target.startswith(base_real + os.sep) and target != base_real:
            return None
        return target
`);
writeFile(`${H01_TARGET}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${H01_TARGET}/test_app.py`, `import os
import pytest
from app import app, file_service


@pytest.fixture
def client():
    file_service.init_storage()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_download(client):
    response = client.get('/api/files/download?filename=readme.txt')
    assert response.status_code == 200
    data = response.get_json()
    assert 'Welcome' in data['content']


def test_list_files(client):
    response = client.get('/api/files/list')
    assert response.status_code == 200
    data = response.get_json()
    assert 'readme.txt' in data['files']


def test_special_input_download(client):
    response = client.get('/api/files/download?filename=../../../../etc/hostname')
    assert response.status_code == 200
    data = response.get_json()
    assert data['content'] != '', 'Expected content from special path'


def test_preview_traversal_blocked(client):
    response = client.get('/api/files/preview?filename=../../../../etc/hostname')
    assert response.status_code == 403


def test_benign_preview(client):
    response = client.get('/api/files/preview?filename=notes.txt')
    assert response.status_code == 200
    data = response.get_json()
    assert 'notes' in data['content'].lower()
`);
writeFile(`${H01_TARGET}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${H01_TARGET}/README.md`, `# Layered File Service\n\nA file management application with service, adapter, and utility layers.\nSupports file download, preview, and listing.\n\n## Architecture\n\napp.py → FileService → StorageAdapter → PathUtils\n\n## Install\n\npip install -r requirements.txt\n\n## Run\n\npython app.py\n\nServer starts on http://127.0.0.1:5201\n\n## Endpoints\n\n- GET /api/files/download?filename=readme.txt — Download a file\n- GET /api/files/preview?filename=readme.txt — Preview a file (first 500 chars)\n- GET /api/files/list — List available files\n\n## Tests\n\npython -m pytest test_app.py -v\n`);

// CASE-H01 FIXED
const H01_FIXED = 'solutions/hard/CASE-H01-path-traversal-layered-FIXED';
writeFile(`${H01_FIXED}/app.py`, `from flask import Flask, request, jsonify
from services.file_service import FileService
from config import Config

app = Flask(__name__)
config = Config()
file_service = FileService(config)


@app.route('/api/files/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename', '')
    if not filename:
        return jsonify({'error': 'filename parameter is required'}), 400
    result = file_service.read_file(filename)
    if result is None:
        return jsonify({'error': 'file not found'}), 404
    if isinstance(result, dict) and 'error' in result:
        return jsonify(result), 403
    return jsonify({'filename': filename, 'content': result})


@app.route('/api/files/preview', methods=['GET'])
def preview_file():
    filename = request.args.get('filename', '')
    if not filename:
        return jsonify({'error': 'filename parameter is required'}), 400
    result = file_service.preview_file(filename)
    if result is None:
        return jsonify({'error': 'file not found'}), 404
    if isinstance(result, dict) and 'error' in result:
        return jsonify(result), 403
    return jsonify({'filename': filename, 'content': result, 'preview': True})


@app.route('/api/files/list', methods=['GET'])
def list_files():
    files = file_service.list_files()
    return jsonify({'files': files})


if __name__ == '__main__':
    file_service.init_storage()
    app.run(host='127.0.0.1', port=5201, debug=True)
`);
writeFile(`${H01_FIXED}/config.py`, `import os


class Config:
    BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'storage')

    def get_base_dir(self):
        return self.BASE_DIR
`);
writeFile(`${H01_FIXED}/services/__init__.py`, '');
writeFile(`${H01_FIXED}/services/file_service.py`, `from adapters.storage_adapter import StorageAdapter


class FileService:
    def __init__(self, config):
        self.config = config
        self.adapter = StorageAdapter(config)

    def read_file(self, filename):
        return self.adapter.read(filename)

    def preview_file(self, filename):
        content = self.adapter.read_preview(filename)
        if content is None:
            return None
        if isinstance(content, str):
            return content[:500]
        return content

    def list_files(self):
        return self.adapter.list_files()

    def init_storage(self):
        self.adapter.init_storage()
`);
writeFile(`${H01_FIXED}/adapters/__init__.py`, '');
writeFile(`${H01_FIXED}/adapters/storage_adapter.py`, `import os
from utils.path_utils import PathUtils


class StorageAdapter:
    def __init__(self, config):
        self.config = config
        self.base_dir = config.get_base_dir()
        self.path_utils = PathUtils()

    def read(self, filename):
        filepath = self.path_utils.join_path_safe(self.base_dir, filename)
        if filepath is None:
            return {'error': 'invalid path'}
        try:
            with open(filepath, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return None
        except IsADirectoryError:
            return {'error': 'path is a directory'}

    def read_preview(self, filename):
        filepath = self.path_utils.join_path_safe(self.base_dir, filename)
        if filepath is None:
            return {'error': 'invalid path'}
        try:
            with open(filepath, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return None
        except IsADirectoryError:
            return {'error': 'path is a directory'}

    def list_files(self):
        if not os.path.exists(self.base_dir):
            return []
        return os.listdir(self.base_dir)

    def init_storage(self):
        os.makedirs(self.base_dir, exist_ok=True)
        for name, content in [('readme.txt', 'Welcome to the file service.\\n'),
                              ('notes.txt', 'Some important notes.\\n'),
                              ('config.txt', 'default configuration\\n')]:
            path = os.path.join(self.base_dir, name)
            with open(path, 'w') as f:
                f.write(content)
`);
writeFile(`${H01_FIXED}/utils/__init__.py`, '');
writeFile(`${H01_FIXED}/utils/path_utils.py`, `import os


class PathUtils:
    def join_path(self, base_dir, filename):
        return os.path.join(base_dir, filename)

    def join_path_safe(self, base_dir, filename):
        base_real = os.path.realpath(base_dir)
        target = os.path.realpath(os.path.join(base_dir, filename))
        if not target.startswith(base_real + os.sep) and target != base_real:
            return None
        return target
`);
writeFile(`${H01_FIXED}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${H01_FIXED}/test_app.py`, `import os
import pytest
from app import app, file_service


@pytest.fixture
def client():
    file_service.init_storage()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_download(client):
    response = client.get('/api/files/download?filename=readme.txt')
    assert response.status_code == 200
    data = response.get_json()
    assert 'Welcome' in data['content']


def test_regression_traversal_blocked(client):
    response = client.get('/api/files/download?filename=../../../../etc/hostname')
    assert response.status_code == 403


def test_benign_still_works(client):
    response = client.get('/api/files/download?filename=notes.txt')
    assert response.status_code == 200


def test_preview_traversal_blocked(client):
    response = client.get('/api/files/preview?filename=../../../../etc/hostname')
    assert response.status_code == 403
`);
writeFile(`${H01_FIXED}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${H01_FIXED}/README.md`, `# Layered File Service (Fixed)\n\nSame functionality with consistent path validation across all code paths.\n\n## Install & Run\n\npip install -r requirements.txt\npython app.py\n`);
writeFile(`${H01_FIXED}/FIX_NOTES.md`, `# Fix Notes — CASE-H01\n\n## Root Cause\nThe StorageAdapter.read() method called PathUtils.join_path() which\nused os.path.join() without validating the resolved path. The read_preview()\nmethod used the safe variant join_path_safe(), but read() did not. This\ninconsistency allowed path traversal through the download endpoint.\n\n## Exact Remediation\n- Changed StorageAdapter.read() to use join_path_safe() instead of\n  join_path(), matching the validation already present in read_preview()\n- Both read and preview paths now use realpath-based validation\n- join_path() still exists for non-security-critical uses\n\n## Why the Exploit No Longer Works\nThe input "../../../../etc/hostname" resolves to a path outside the\nbase directory, which is detected by join_path_safe()'s prefix check,\nresulting in a 403 Forbidden response.\n\n## Trade-offs\n- realpath resolves symlinks, which could reject legitimate symlinks\n  inside the storage directory (acceptable for security)\n`);

// CASE-H02
const H02_TARGET = 'benchmark_targets/hard/CASE-H02-ldap-injection';
writeFile(`${H02_TARGET}/app.py`, `from flask import Flask, request, jsonify
from services.auth_service import AuthService
from config import Config

app = Flask(__name__)
config = Config()
auth_service = AuthService(config)


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'username and password are required'}), 400

    result = auth_service.authenticate(username, password)
    if result['authenticated']:
        return jsonify({'status': 'success', 'user': result['user']})
    return jsonify({'status': 'failed', 'message': 'invalid credentials'}), 401


@app.route('/api/auth/lookup', methods=['GET'])
def lookup_user():
    username = request.args.get('username', '')
    if not username:
        return jsonify({'error': 'username parameter is required'}), 400

    result = auth_service.lookup_user(username)
    if result:
        return jsonify({'found': True, 'user': result})
    return jsonify({'found': False})


@app.route('/api/auth/verify/<int:user_id>', methods=['GET'])
def verify_user(user_id):
    result = auth_service.verify_by_id(user_id)
    if result:
        return jsonify({'valid': True, 'user': result})
    return jsonify({'valid': False}), 404


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5202, debug=True)
`);
writeFile(`${H02_TARGET}/config.py`, `class Config:\n    LDAP_BASE_DN = 'dc=example,dc=com'\n    LDAP_SERVER = 'mock://localhost'\n`);
writeFile(`${H02_TARGET}/services/__init__.py`, '');
writeFile(`${H02_TARGET}/services/auth_service.py`, `from services.ldap_service import LDAPService


class AuthService:
    def __init__(self, config):
        self.ldap_service = LDAPService(config)

    def authenticate(self, username, password):
        filter_str = f'(&(cn={username})(userPassword={password}))'
        results = self.ldap_service.search(filter_str)
        if results:
            return {'authenticated': True, 'user': results[0]}
        return {'authenticated': False}

    def lookup_user(self, username):
        filter_str = f'(cn={username})'
        results = self.ldap_service.search(filter_str)
        if results:
            return results[0]
        return None

    def verify_by_id(self, user_id):
        filter_str = f'(employeeNumber={user_id})'
        results = self.ldap_service.search(filter_str)
        if results:
            return results[0]
        return None
`);
writeFile(`${H02_TARGET}/services/ldap_service.py`, `from repositories.ldap_repository import MockLDAPRepository


class LDAPService:
    def __init__(self, config):
        self.config = config
        self.repository = MockLDAPRepository()

    def search(self, filter_str):
        return self.repository.search(
            self.config.LDAP_BASE_DN,
            filter_str
        )
`);
writeFile(`${H02_TARGET}/repositories/__init__.py`, '');
writeFile(`${H02_TARGET}/repositories/ldap_repository.py`, `import re


class MockLDAPRepository:
    """Simulates an LDAP directory server with local data."""

    def __init__(self):
        self._entries = [
            {
                'dn': 'cn=admin,dc=example,dc=com',
                'cn': 'admin',
                'userPassword': 'admin123',
                'role': 'admin',
                'mail': 'admin@example.com',
                'employeeNumber': '1',
                'objectClass': 'inetOrgPerson',
            },
            {
                'dn': 'cn=user1,dc=example,dc=com',
                'cn': 'user1',
                'userPassword': 'pass1',
                'role': 'user',
                'mail': 'user1@example.com',
                'employeeNumber': '2',
                'objectClass': 'inetOrgPerson',
            },
            {
                'dn': 'cn=user2,dc=example,dc=com',
                'cn': 'user2',
                'userPassword': 'pass2',
                'role': 'user',
                'mail': 'user2@example.com',
                'employeeNumber': '3',
                'objectClass': 'inetOrgPerson',
            },
        ]

    def search(self, base_dn, filter_str):
        results = []
        for entry in self._entries:
            if self._match_filter(entry, filter_str):
                safe_entry = {k: v for k, v in entry.items() if k != 'userPassword'}
                results.append(safe_entry)
        return results

    def _match_filter(self, entry, filter_str):
        filter_str = filter_str.strip()
        if not filter_str:
            return True

        if filter_str.startswith('(&'):
            inner = filter_str[2:]
            if inner.endswith(')'):
                inner = inner[:-1]
            if not inner:
                return True
            sub_filters = self._extract_sub_filters(inner)
            return all(self._match_filter(entry, f) for f in sub_filters)

        if filter_str.startswith('(|'):
            inner = filter_str[2:]
            if inner.endswith(')'):
                inner = inner[:-1]
            if not inner:
                return False
            sub_filters = self._extract_sub_filters(inner)
            return any(self._match_filter(entry, f) for f in sub_filters)

        if filter_str.startswith('(!'):
            inner = filter_str[2:]
            if inner.endswith(')'):
                inner = inner[:-1]
            return not self._match_filter(entry, inner)

        m = re.match(r'^\\(([^=]+)=(.*)\\)$', filter_str)
        if m:
            attr = m.group(1)
            value = m.group(2)
            if value == '*':
                return attr in entry and entry[attr] is not None
            return entry.get(attr) == value

        return False

    def _extract_sub_filters(self, s):
        filters = []
        depth = 0
        start = 0
        for i, c in enumerate(s):
            if c == '(':
                if depth == 0:
                    start = i
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    filters.append(s[start:i + 1])
        return filters
`);
writeFile(`${H02_TARGET}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${H02_TARGET}/test_app.py`, `import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_login(client):
    response = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin123'})
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'success'


def test_wrong_password(client):
    response = client.post('/api/auth/login', json={'username': 'admin', 'password': 'wrong'})
    assert response.status_code == 401


def test_lookup_user(client):
    response = client.get('/api/auth/lookup?username=admin')
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is True


def test_special_input_auth(client):
    response = client.post('/api/auth/login', json={
        'username': 'admin)(|(userPassword=*',
        'password': 'anything'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'success', 'Expected auth bypass with special input'


def test_verify_by_id(client):
    response = client.get('/api/auth/verify/1')
    assert response.status_code == 200
    data = response.get_json()
    assert data['valid'] is True


def test_verify_wrong_id(client):
    response = client.get('/api/auth/verify/999')
    assert response.status_code == 404
`);
writeFile(`${H02_TARGET}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${H02_TARGET}/README.md`, `# Authentication Service\n\nA directory-based authentication service with user lookup and verification.\nUses an LDAP-style directory for credential management.\n\n## Architecture\n\napp.py → AuthService → LDAPService → MockLDAPRepository\n\n## Install\n\npip install -r requirements.txt\n\n## Run\n\npython app.py\n\nServer starts on http://127.0.0.1:5202\n\n## Endpoints\n\n- POST /api/auth/login — Authenticate user (body: {"username":"admin","password":"admin123"})\n- GET  /api/auth/lookup?username=admin — Look up user by name\n- GET  /api/auth/verify/1 — Verify user by employee number\n\n## Tests\n\npython -m pytest test_app.py -v\n`);

// CASE-H02 FIXED
const H02_FIXED = 'solutions/hard/CASE-H02-ldap-injection-FIXED';
writeFile(`${H02_FIXED}/app.py`, `from flask import Flask, request, jsonify
from services.auth_service import AuthService
from config import Config

app = Flask(__name__)
config = Config()
auth_service = AuthService(config)


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'username and password are required'}), 400

    result = auth_service.authenticate(username, password)
    if result['authenticated']:
        return jsonify({'status': 'success', 'user': result['user']})
    return jsonify({'status': 'failed', 'message': 'invalid credentials'}), 401


@app.route('/api/auth/lookup', methods=['GET'])
def lookup_user():
    username = request.args.get('username', '')
    if not username:
        return jsonify({'error': 'username parameter is required'}), 400

    result = auth_service.lookup_user(username)
    if result:
        return jsonify({'found': True, 'user': result})
    return jsonify({'found': False})


@app.route('/api/auth/verify/<int:user_id>', methods=['GET'])
def verify_user(user_id):
    result = auth_service.verify_by_id(user_id)
    if result:
        return jsonify({'valid': True, 'user': result})
    return jsonify({'valid': False}), 404


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5202, debug=True)
`);
writeFile(`${H02_FIXED}/config.py`, `class Config:\n    LDAP_BASE_DN = 'dc=example,dc=com'\n    LDAP_SERVER = 'mock://localhost'\n`);
writeFile(`${H02_FIXED}/services/__init__.py`, '');
writeFile(`${H02_FIXED}/services/auth_service.py`, `from services.ldap_service import LDAPService


class AuthService:
    def __init__(self, config):
        self.ldap_service = LDAPService(config)

    def authenticate(self, username, password):
        filter_str = self.ldap_service.build_filter(
            'cn', username
        )
        results = self.ldap_service.search(filter_str)
        if results:
            entry = results[0]
            if self.ldap_service.verify_password(username, password):
                return {'authenticated': True, 'user': entry}
        return {'authenticated': False}

    def lookup_user(self, username):
        filter_str = self.ldap_service.build_filter('cn', username)
        results = self.ldap_service.search(filter_str)
        if results:
            return results[0]
        return None

    def verify_by_id(self, user_id):
        filter_str = self.ldap_service.build_filter('employeeNumber', str(user_id))
        results = self.ldap_service.search(filter_str)
        if results:
            return results[0]
        return None
`);
writeFile(`${H02_FIXED}/services/ldap_service.py`, `import re
from repositories.ldap_repository import MockLDAPRepository


class LDAPService:
    SAFE_CHARS = re.compile(r'^[a-zA-Z0-9._\\-@]+$')

    def __init__(self, config):
        self.config = config
        self.repository = MockLDAPRepository()

    def build_filter(self, attr, value):
        if not self.SAFE_CHARS.match(value):
            return None
        return f'({attr}={value})'

    def verify_password(self, username, password):
        entries = self.repository.get_raw_entries()
        for entry in entries:
            if entry.get('cn') == username:
                return entry.get('userPassword') == password
        return False

    def search(self, filter_str):
        if filter_str is None:
            return []
        return self.repository.search(
            self.config.LDAP_BASE_DN,
            filter_str
        )
`);
writeFile(`${H02_FIXED}/repositories/__init__.py`, '');
writeFile(`${H02_FIXED}/repositories/ldap_repository.py`, `import re


class MockLDAPRepository:
    """Simulates an LDAP directory server with local data."""

    def __init__(self):
        self._entries = [
            {
                'dn': 'cn=admin,dc=example,dc=com',
                'cn': 'admin',
                'userPassword': 'admin123',
                'role': 'admin',
                'mail': 'admin@example.com',
                'employeeNumber': '1',
                'objectClass': 'inetOrgPerson',
            },
            {
                'dn': 'cn=user1,dc=example,dc=com',
                'cn': 'user1',
                'userPassword': 'pass1',
                'role': 'user',
                'mail': 'user1@example.com',
                'employeeNumber': '2',
                'objectClass': 'inetOrgPerson',
            },
            {
                'dn': 'cn=user2,dc=example,dc=com',
                'cn': 'user2',
                'userPassword': 'pass2',
                'role': 'user',
                'mail': 'user2@example.com',
                'employeeNumber': '3',
                'objectClass': 'inetOrgPerson',
            },
        ]

    def get_raw_entries(self):
        return self._entries

    def search(self, base_dn, filter_str):
        results = []
        for entry in self._entries:
            if self._match_filter(entry, filter_str):
                safe_entry = {k: v for k, v in entry.items() if k != 'userPassword'}
                results.append(safe_entry)
        return results

    def _match_filter(self, entry, filter_str):
        filter_str = filter_str.strip()
        if not filter_str:
            return True

        if filter_str.startswith('(&'):
            inner = filter_str[2:]
            if inner.endswith(')'):
                inner = inner[:-1]
            if not inner:
                return True
            sub_filters = self._extract_sub_filters(inner)
            return all(self._match_filter(entry, f) for f in sub_filters)

        if filter_str.startswith('(|'):
            inner = filter_str[2:]
            if inner.endswith(')'):
                inner = inner[:-1]
            if not inner:
                return False
            sub_filters = self._extract_sub_filters(inner)
            return any(self._match_filter(entry, f) for f in sub_filters)

        if filter_str.startswith('(!'):
            inner = filter_str[2:]
            if inner.endswith(')'):
                inner = inner[:-1]
            return not self._match_filter(entry, inner)

        m = re.match(r'^\\(([^=]+)=(.*)\\)$', filter_str)
        if m:
            attr = m.group(1)
            value = m.group(2)
            if value == '*':
                return attr in entry and entry[attr] is not None
            return entry.get(attr) == value

        return False

    def _extract_sub_filters(self, s):
        filters = []
        depth = 0
        start = 0
        for i, c in enumerate(s):
            if c == '(':
                if depth == 0:
                    start = i
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    filters.append(s[start:i + 1])
        return filters
`);
writeFile(`${H02_FIXED}/requirements.txt`, `flask>=3.0\npytest>=7.0`);
writeFile(`${H02_FIXED}/test_app.py`, `import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_login(client):
    response = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin123'})
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'success'


def test_regression_injection_blocked(client):
    response = client.post('/api/auth/login', json={
        'username': 'admin)(|(userPassword=*',
        'password': 'anything'
    })
    assert response.status_code == 401


def test_benign_login_still_works(client):
    response = client.post('/api/auth/login', json={'username': 'user1', 'password': 'pass1'})
    assert response.status_code == 200


def test_wrong_password(client):
    response = client.post('/api/auth/login', json={'username': 'admin', 'password': 'wrong'})
    assert response.status_code == 401
`);
writeFile(`${H02_FIXED}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${H02_FIXED}/README.md`, `# Authentication Service (Fixed)\n\nSame functionality with input validation and separated authentication.\n\n## Install & Run\n\npip install -r requirements.txt\npython app.py\n`);
writeFile(`${H02_FIXED}/FIX_NOTES.md`, `# Fix Notes — CASE-H02\n\n## Root Cause\nThe AuthService.authenticate() method built an LDAP filter by\nconcatenating user input directly into the filter string:\n  (&(cn={username})(userPassword={password}))\nThis allowed LDAP injection to bypass the password check.\n\n## Exact Remediation\n- Separated authentication into two steps:\n  1. Search for user by cn (with input validation)\n  2. Verify password programmatically against the found entry\n- Added LDAPService.build_filter() that validates input against\n  a safe character set (alphanumerics, dots, hyphens, underscores, @)\n- If input contains special characters, the filter is not built\n  and authentication fails\n\n## Why the Exploit No Longer Works\nThe input "admin)(|(userPassword=*" contains parentheses and\nasterisks, which fail the SAFE_CHARS regex. The filter is not\nbuilt, search returns empty, and authentication fails with 401.\n\n## Trade-offs\n- Usernames with special characters (e.g., spaces) are rejected\n  (acceptable for cn-based lookups)\n- Password verification is now application-side rather than\n  filter-side, which is actually more secure\n`);

// CASE-H03
const H03_TARGET = 'benchmark_targets/hard/CASE-H03-xpath-injection';
writeFile(`${H03_TARGET}/app.py`, `from flask import Flask, request, jsonify
from services.user_service import UserService
from config import Config

app = Flask(__name__)
config = Config()
user_service = UserService(config)


@app.route('/api/user/search', methods=['GET'])
def search_user():
    username = request.args.get('username', '')
    if not username:
        return jsonify({'error': 'username parameter is required'}), 400
    result = user_service.find_user(username)
    if result:
        return jsonify({'found': True, 'user': result})
    return jsonify({'found': False})


@app.route('/api/user/search_by_email', methods=['GET'])
def search_by_email():
    email = request.args.get('email', '')
    if not email:
        return jsonify({'error': 'email parameter is required'}), 400
    result = user_service.find_user_by_email(email)
    if result:
        return jsonify({'found': True, 'user': result})
    return jsonify({'found': False})


@app.route('/api/user/by_id/<int:user_id>', methods=['GET'])
def get_by_id(user_id):
    result = user_service.get_user_by_id(user_id)
    if result:
        return jsonify({'found': True, 'user': result})
    return jsonify({'found': False}), 404


@app.route('/api/user/list', methods=['GET'])
def list_users():
    users = user_service.list_all_users()
    return jsonify({'users': users, 'count': len(users)})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5203, debug=True)
`);
writeFile(`${H03_TARGET}/config.py`, `import os


class Config:
    DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    XML_FILE = os.path.join(DATA_DIR, 'users.xml')
`);
writeFile(`${H03_TARGET}/services/__init__.py`, '');
writeFile(`${H03_TARGET}/services/user_service.py`, `from repositories.xml_repository import XMLRepository
from query.query_builder import QueryBuilder


class UserService:
    def __init__(self, config):
        self.repository = XMLRepository(config.XML_FILE)
        self.query_builder = QueryBuilder()

    def find_user(self, username):
        xpath = self.query_builder.build_username_query(username)
        return self.repository.find_single(xpath)

    def find_user_by_email(self, email):
        xpath = self.query_builder.build_email_query(email)
        return self.repository.find_single(xpath)

    def get_user_by_id(self, user_id):
        xpath = self.query_builder.build_id_query(user_id)
        return self.repository.find_single(xpath)

    def list_all_users(self):
        return self.repository.find_all()
`);
writeFile(`${H03_TARGET}/repositories/__init__.py`, '');
writeFile(`${H03_TARGET}/repositories/xml_repository.py`, `from lxml import etree


class XMLRepository:
    def __init__(self, xml_path):
        self.tree = etree.parse(xml_path)
        self.root = self.tree.getroot()

    def find_single(self, xpath):
        results = self.root.xpath(xpath)
        if results:
            return self._element_to_dict(results[0])
        return None

    def find_all(self):
        elements = self.root.findall('.//user')
        return [self._element_to_dict(e) for e in elements]

    def _element_to_dict(self, element):
        data = {}
        for child in element:
            data[child.tag] = child.text
        data['id'] = element.get('id')
        return data
`);
writeFile(`${H03_TARGET}/query/__init__.py`, '');
writeFile(`${H03_TARGET}/query/query_builder.py`, `class QueryBuilder:
    def build_username_query(self, username):
        return f"//user[name='{username}']"

    def build_email_query(self, email):
        return f"//user[email='{email}']"

    def build_id_query(self, user_id):
        return f"//user[@id='{user_id}']"
`);
writeFile(`${H03_TARGET}/data/users.xml`, `<?xml version="1.0" encoding="UTF-8"?>
<directory>
    <user id="1">
        <name>admin</name>
        <email>admin@example.com</email>
        <role>admin</role>
        <department>IT</department>
    </user>
    <user id="2">
        <name>alice</name>
        <email>alice@example.com</email>
        <role>user</role>
        <department>Engineering</department>
    </user>
    <user id="3">
        <name>bob</name>
        <email>bob@example.com</email>
        <role>user</role>
        <department>Marketing</department>
    </user>
    <user id="4">
        <name>charlie</name>
        <email>charlie@example.com</email>
        <role>manager</role>
        <department>Engineering</department>
    </user>
</directory>
`);
writeFile(`${H03_TARGET}/requirements.txt`, `flask>=3.0\nlxml>=5.0\npytest>=7.0`);
writeFile(`${H03_TARGET}/test_app.py`, `import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_search(client):
    response = client.get('/api/user/search?username=alice')
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is True
    assert data['user']['name'] == 'alice'


def test_search_not_found(client):
    response = client.get('/api/user/search?username=nonexistent')
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is False


def test_special_input_search(client):
    response = client.get("/api/user/search?username=' or '1'='1")
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is True
    assert 'name' in data['user'], 'Expected user data from special input'


def test_by_id(client):
    response = client.get('/api/user/by_id/1')
    assert response.status_code == 200
    data = response.get_json()
    assert data['user']['name'] == 'admin'


def test_by_id_not_found(client):
    response = client.get('/api/user/by_id/999')
    assert response.status_code == 404


def test_list_users(client):
    response = client.get('/api/user/list')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 4


def test_search_by_email(client):
    response = client.get('/api/user/search_by_email?email=alice@example.com')
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is True
`);
writeFile(`${H03_TARGET}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${H03_TARGET}/README.md`, `# XML User Directory\n\nA user directory service backed by XML data, with XPath-based querying.\n\n## Architecture\n\napp.py → UserService → QueryBuilder + XMLRepository → lxml\n\n## Install\n\npip install -r requirements.txt\n\n## Run\n\npython app.py\n\nServer starts on http://127.0.0.1:5203\n\n## Endpoints\n\n- GET /api/user/search?username=alice — Search by username\n- GET /api/user/search_by_email?email=alice@example.com — Search by email\n- GET /api/user/by_id/1 — Get user by ID\n- GET /api/user/list — List all users\n\n## Tests\n\npython -m pytest test_app.py -v\n`);

// CASE-H03 FIXED
const H03_FIXED = 'solutions/hard/CASE-H03-xpath-injection-FIXED';
writeFile(`${H03_FIXED}/app.py`, `from flask import Flask, request, jsonify
from services.user_service import UserService
from config import Config

app = Flask(__name__)
config = Config()
user_service = UserService(config)


@app.route('/api/user/search', methods=['GET'])
def search_user():
    username = request.args.get('username', '')
    if not username:
        return jsonify({'error': 'username parameter is required'}), 400
    result = user_service.find_user(username)
    if result:
        return jsonify({'found': True, 'user': result})
    return jsonify({'found': False})


@app.route('/api/user/search_by_email', methods=['GET'])
def search_by_email():
    email = request.args.get('email', '')
    if not email:
        return jsonify({'error': 'email parameter is required'}), 400
    result = user_service.find_user_by_email(email)
    if result:
        return jsonify({'found': True, 'user': result})
    return jsonify({'found': False})


@app.route('/api/user/by_id/<int:user_id>', methods=['GET'])
def get_by_id(user_id):
    result = user_service.get_user_by_id(user_id)
    if result:
        return jsonify({'found': True, 'user': result})
    return jsonify({'found': False}), 404


@app.route('/api/user/list', methods=['GET'])
def list_users():
    users = user_service.list_all_users()
    return jsonify({'users': users, 'count': len(users)})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5203, debug=True)
`);
writeFile(`${H03_FIXED}/config.py`, `import os


class Config:
    DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    XML_FILE = os.path.join(DATA_DIR, 'users.xml')
`);
writeFile(`${H03_FIXED}/services/__init__.py`, '');
writeFile(`${H03_FIXED}/services/user_service.py`, `from repositories.xml_repository import XMLRepository


class UserService:
    def __init__(self, config):
        self.repository = XMLRepository(config.XML_FILE)

    def find_user(self, username):
        return self.repository.find_by_field('name', username)

    def find_user_by_email(self, email):
        return self.repository.find_by_field('email', email)

    def get_user_by_id(self, user_id):
        return self.repository.find_by_id(user_id)

    def list_all_users(self):
        return self.repository.find_all()
`);
writeFile(`${H03_FIXED}/repositories/__init__.py`, '');
writeFile(`${H03_FIXED}/repositories/xml_repository.py`, `from lxml import etree


class XMLRepository:
    def __init__(self, xml_path):
        self.tree = etree.parse(xml_path)
        self.root = self.tree.getroot()

    def find_by_field(self, field_name, value):
        for user_elem in self.root.findall('.//user'):
            field_elem = user_elem.find(field_name)
            if field_elem is not None and field_elem.text == value:
                return self._element_to_dict(user_elem)
        return None

    def find_by_id(self, user_id):
        user_elem = self.root.find(f'.//user[@id="{int(user_id)}"]')
        if user_elem is not None:
            return self._element_to_dict(user_elem)
        return None

    def find_all(self):
        elements = self.root.findall('.//user')
        return [self._element_to_dict(e) for e in elements]

    def _element_to_dict(self, element):
        data = {}
        for child in element:
            data[child.tag] = child.text
        data['id'] = element.get('id')
        return data
`);
writeFile(`${H03_FIXED}/query/__init__.py`, '');
writeFile(`${H03_FIXED}/query/query_builder.py`, `class QueryBuilder:
    """Legacy query builder - kept for API compatibility."""

    def build_username_query(self, username):
        raise DeprecationWarning("Use XMLRepository.find_by_field instead")

    def build_email_query(self, email):
        raise DeprecationWarning("Use XMLRepository.find_by_field instead")

    def build_id_query(self, user_id):
        return f"//user[@id='{int(user_id)}']"
`);
writeFile(`${H03_FIXED}/data/users.xml`, `<?xml version="1.0" encoding="UTF-8"?>
<directory>
    <user id="1">
        <name>admin</name>
        <email>admin@example.com</email>
        <role>admin</role>
        <department>IT</department>
    </user>
    <user id="2">
        <name>alice</name>
        <email>alice@example.com</email>
        <role>user</role>
        <department>Engineering</department>
    </user>
    <user id="3">
        <name>bob</name>
        <email>bob@example.com</email>
        <role>user</role>
        <department>Marketing</department>
    </user>
    <user id="4">
        <name>charlie</name>
        <email>charlie@example.com</email>
        <role>manager</role>
        <department>Engineering</department>
    </user>
</directory>
`);
writeFile(`${H03_FIXED}/requirements.txt`, `flask>=3.0\nlxml>=5.0\npytest>=7.0`);
writeFile(`${H03_FIXED}/test_app.py`, `import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_search(client):
    response = client.get('/api/user/search?username=alice')
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is True
    assert data['user']['name'] == 'alice'


def test_regression_injection_blocked(client):
    response = client.get("/api/user/search?username=' or '1'='1")
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is False


def test_benign_still_works(client):
    response = client.get('/api/user/search?username=admin')
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is True


def test_list_users(client):
    response = client.get('/api/user/list')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 4
`);
writeFile(`${H03_FIXED}/run.sh`, `#!/bin/bash\npip install -r requirements.txt\npython app.py`);
writeFile(`${H03_FIXED}/README.md`, `# XML User Directory (Fixed)\n\nSame functionality with direct XML element comparison instead of\nstring-interpolated XPath queries.\n\n## Install & Run\n\npip install -r requirements.txt\npython app.py\n`);
writeFile(`${H03_FIXED}/FIX_NOTES.md`, `# Fix Notes — CASE-H03\n\n## Root Cause\nThe QueryBuilder built XPath query strings by interpolating user input:\n  //user[name='{username}']\nThe UserService passed user input through QueryBuilder to XMLRepository,\nwhich executed the raw XPath. This allowed XPath injection via quotes\nand boolean operators.\n\n## Exact Remediation\n- Replaced string-interpolated XPath queries with direct element\n  comparison using lxml's find/findall API\n- XMLRepository.find_by_field() iterates user elements and compares\n  the field text directly, avoiding XPath injection\n- find_by_id() uses int() conversion before building the XPath,\n  ensuring only numeric values reach the query\n- QueryBuilder is deprecated but kept for API compatibility\n\n## Why the Exploit No Longer Works\nThe input "' or '1'='1" is compared literally against each <name>\nelement's text content. No user has that literal name, so no match\nis found and the response returns found: false.\n\n## Trade-offs\n- Slightly slower for large XML files (iterative scan vs XPath engine)\n  but acceptable for the dataset size in this application\n`);

// ── ANSWER KEY ───────────────────────────────────────────────────────────────

const MANIFEST_JSON = {
  "benchmark_version": "1.0",
  "generated": "2025-01-15",
  "cases": [
    {
      "case_id": "CASE-E01",
      "difficulty": "easy",
      "vulnerability_class": "CWE-78 OS Command Injection",
      "primary_entry_point": "POST /api/diagnostic/ping",
      "vulnerable_files": ["app.py"],
      "source_to_sink": "request.json['host'] -> subprocess.run(shell=True, f'ping ... {host}')",
      "exploit_witness": "POST /api/diagnostic/ping with body {\"host\": \"127.0.0.1; touch /tmp/hwsec_e01_marker\"}",
      "expected_security_effect": "Marker file /tmp/hwsec_e01_marker is created via shell injection",
      "negative_control": "POST /api/diagnostic/ping with body {\"host\": \"127.0.0.1\"} — no marker created",
      "fixed_solution_path": "solutions/easy/CASE-E01-command-injection-FIXED",
      "regression_test_command": "cd solutions/easy/CASE-E01-command-injection-FIXED && python -m pytest test_app.py::test_regression_injection_blocked -v",
      "expected_hwsec_classification": "DETECTED",
      "known_limitations": "Requires Linux with /bin/sh; ping optional",
      "approximate_runtime": "< 5 seconds"
    },
    {
      "case_id": "CASE-E02",
      "difficulty": "easy",
      "vulnerability_class": "CWE-89 SQL Injection",
      "primary_entry_point": "GET /api/users/search?username=",
      "vulnerable_files": ["app.py"],
      "source_to_sink": "request.args['username'] -> string concatenation into SQL SELECT",
      "exploit_witness": "GET /api/users/search?username=' OR '1'='1",
      "expected_security_effect": "All user records returned instead of single match",
      "negative_control": "GET /api/users/search?username=alice — single result returned",
      "fixed_solution_path": "solutions/easy/CASE-E02-sql-injection-FIXED",
      "regression_test_command": "cd solutions/easy/CASE-E02-sql-injection-FIXED && python -m pytest test_app.py::test_regression_injection_blocked -v",
      "expected_hwsec_classification": "DETECTED",
      "known_limitations": "Uses in-memory SQLite; DB initialized at module load",
      "approximate_runtime": "< 3 seconds"
    },
    {
      "case_id": "CASE-E03",
      "difficulty": "easy",
      "vulnerability_class": "CWE-22 Path Traversal",
      "primary_entry_point": "GET /api/files/download?filename=",
      "vulnerable_files": ["app.py"],
      "source_to_sink": "request.args['filename'] -> os.path.join(BASE_DIR, filename) -> open()",
      "exploit_witness": "GET /api/files/download?filename=../../../../etc/hostname",
      "expected_security_effect": "Contents of /etc/hostname returned (file outside files directory)",
      "negative_control": "GET /api/files/download?filename=hello.txt — normal file returned",
      "fixed_solution_path": "solutions/easy/CASE-E03-path-traversal-FIXED",
      "regression_test_command": "cd solutions/easy/CASE-E03-path-traversal-FIXED && python -m pytest test_app.py::test_regression_traversal_blocked -v",
      "expected_hwsec_classification": "DETECTED",
      "known_limitations": "Requires /etc/hostname to exist (standard on Linux)",
      "approximate_runtime": "< 3 seconds"
    },
    {
      "case_id": "CASE-M01",
      "difficulty": "medium",
      "vulnerability_class": "CWE-79 Cross-Site Scripting (Reflected)",
      "primary_entry_point": "GET /search?q=",
      "vulnerable_files": ["app.py", "services/search_service.py", "templates/search.html"],
      "source_to_sink": "request.args['q'] -> SearchService._sanitize() (incomplete) -> render_template(query | safe)",
      "exploit_witness": "GET /search?q=<img src=x onerror=alert(1)>",
      "expected_security_effect": "Unescaped HTML reflected in response body",
      "negative_control": "GET /api/products/1 — JSON response, no HTML rendering",
      "fixed_solution_path": "solutions/medium/CASE-M01-xss-reflection-FIXED",
      "regression_test_command": "cd solutions/medium/CASE-M01-xss-reflection-FIXED && python -m pytest test_app.py::test_regression_xss_blocked -v",
      "expected_hwsec_classification": "DETECTED",
      "known_limitations": "XSS demonstrated via response inspection, not browser execution",
      "approximate_runtime": "< 3 seconds"
    },
    {
      "case_id": "CASE-M02",
      "difficulty": "medium",
      "vulnerability_class": "CWE-89 SQL Injection",
      "primary_entry_point": "GET /api/users/search?pattern=",
      "vulnerable_files": ["app.py", "services/user_service.py", "repositories/user_repository.py"],
      "source_to_sink": "request.args['pattern'] -> UserService.find_users_by_pattern() -> UserRepository.search_users() (string concat in SQL LIKE)",
      "exploit_witness": "GET /api/users/search?pattern=' UNION SELECT id, username, email, role, department FROM users-- ",
      "expected_security_effect": "All user records returned via UNION injection",
      "negative_control": "GET /api/users/by_role/user — parameterized query, safe",
      "fixed_solution_path": "solutions/medium/CASE-M02-sql-injection-indirect-FIXED",
      "regression_test_command": "cd solutions/medium/CASE-M02-sql-injection-indirect-FIXED && python -m pytest test_app.py::test_regression_injection_blocked -v",
      "expected_hwsec_classification": "DETECTED",
      "known_limitations": "In-memory SQLite; requires source/data-flow reasoning through 3 files",
      "approximate_runtime": "< 3 seconds"
    },
    {
      "case_id": "CASE-M03",
      "difficulty": "medium",
      "vulnerability_class": "CWE-78 OS Command Injection",
      "primary_entry_point": "POST /api/diagnostic/run (tool=ping)",
      "vulnerable_files": ["app.py", "services/diagnostic_service.py"],
      "source_to_sink": "request.json['target'] -> DiagnosticService._run_ping() -> subprocess.run(shell=True, f'ping ... {target}')",
      "exploit_witness": "POST /api/diagnostic/run with {\"target\": \"127.0.0.1; touch /tmp/hwsec_m03_marker\", \"tool\": \"ping\"}",
      "expected_security_effect": "Marker file created via shell injection on ping tool path",
      "negative_control": "POST /api/diagnostic/run with tool=traceroute — uses argument list, no injection",
      "fixed_solution_path": "solutions/medium/CASE-M03-command-injection-conditional-FIXED",
      "regression_test_command": "cd solutions/medium/CASE-M03-command-injection-conditional-FIXED && python -m pytest test_app.py::test_regression_injection_blocked -v",
      "expected_hwsec_classification": "DETECTED",
      "known_limitations": "Conditional vulnerability; only ping tool is vulnerable",
      "approximate_runtime": "< 5 seconds"
    },
    {
      "case_id": "CASE-H01",
      "difficulty": "hard",
      "vulnerability_class": "CWE-22 Path Traversal",
      "primary_entry_point": "GET /api/files/download?filename=",
      "vulnerable_files": ["app.py", "services/file_service.py", "adapters/storage_adapter.py", "utils/path_utils.py", "config.py"],
      "source_to_sink": "request.args['filename'] -> FileService.read_file() -> StorageAdapter.read() -> PathUtils.join_path() (no validation) -> open()",
      "exploit_witness": "GET /api/files/download?filename=../../../../etc/hostname",
      "expected_security_effect": "File outside storage directory returned via download endpoint",
      "negative_control": "GET /api/files/preview?filename=../../../../etc/hostname — uses join_path_safe(), returns 403",
      "fixed_solution_path": "solutions/hard/CASE-H01-path-traversal-layered-FIXED",
      "regression_test_command": "cd solutions/hard/CASE-H01-path-traversal-layered-FIXED && python -m pytest test_app.py::test_regression_traversal_blocked -v",
      "expected_hwsec_classification": "DETECTED",
      "known_limitations": "Requires tracing through 4 layers; false-positive trap at /api/files/preview",
      "approximate_runtime": "< 5 seconds"
    },
    {
      "case_id": "CASE-H02",
      "difficulty": "hard",
      "vulnerability_class": "CWE-90 LDAP Injection",
      "primary_entry_point": "POST /api/auth/login",
      "vulnerable_files": ["app.py", "services/auth_service.py", "services/ldap_service.py", "repositories/ldap_repository.py", "config.py"],
      "source_to_sink": "request.json['username'] -> AuthService.authenticate() -> f'(&(cn={username})(userPassword={password}))' -> LDAPService.search() -> MockLDAPRepository.search()",
      "exploit_witness": "POST /api/auth/login with {\"username\": \"admin)(|(userPassword=*\", \"password\": \"anything\"}",
      "expected_security_effect": "Authentication bypassed; login succeeds with wrong password",
      "negative_control": "GET /api/auth/verify/1 — uses employeeNumber filter, no user input in filter structure",
      "fixed_solution_path": "solutions/hard/CASE-H02-ldap-injection-FIXED",
      "regression_test_command": "cd solutions/hard/CASE-H02-ldap-injection-FIXED && python -m pytest test_app.py::test_regression_injection_blocked -v",
      "expected_hwsec_classification": "DETECTED",
      "known_limitations": "Uses mock LDAP (not real server); requires understanding LDAP filter semantics",
      "approximate_runtime": "< 3 seconds"
    },
    {
      "case_id": "CASE-H03",
      "difficulty": "hard",
      "vulnerability_class": "CWE-643 XPath Injection",
      "primary_entry_point": "GET /api/user/search?username=",
      "vulnerable_files": ["app.py", "services/user_service.py", "repositories/xml_repository.py", "query/query_builder.py", "config.py"],
      "source_to_sink": "request.args['username'] -> UserService.find_user() -> QueryBuilder.build_username_query() -> f\"//user[name='{username}']\" -> XMLRepository.find_single() -> root.xpath()",
      "exploit_witness": "GET /api/user/search?username=' or '1'='1",
      "expected_security_effect": "First user record returned without exact match (injected boolean OR)",
      "negative_control": "GET /api/user/by_id/1 — uses int-typed parameter, safe from injection",
      "fixed_solution_path": "solutions/hard/CASE-H03-xpath-injection-FIXED",
      "regression_test_command": "cd solutions/hard/CASE-H03-xpath-injection-FIXED && python -m pytest test_app.py::test_regression_injection_blocked -v",
      "expected_hwsec_classification": "DETECTED",
      "known_limitations": "Requires lxml; false-positive trap at /api/user/by_id (string XPath but int input)",
      "approximate_runtime": "< 3 seconds"
    }
  ]
};

writeFile('answer_key/benchmark_manifest.json', JSON.stringify(MANIFEST_JSON, null, 2));

writeFile('answer_key/expected_findings.md', `# Expected Findings

## Summary Table

| Case ID  | Difficulty | CWE    | Vulnerability        | Entry Point                          | Expected HWSEC Result |
|----------|------------|--------|----------------------|--------------------------------------|-----------------------|
| CASE-E01 | Easy       | CWE-78 | Command Injection    | POST /api/diagnostic/ping            | DETECTED              |
| CASE-E02 | Easy       | CWE-89 | SQL Injection        | GET /api/users/search                | DETECTED              |
| CASE-E03 | Easy       | CWE-22 | Path Traversal       | GET /api/files/download              | DETECTED              |
| CASE-M01 | Medium     | CWE-79 | XSS (Reflected)      | GET /search                          | DETECTED              |
| CASE-M02 | Medium     | CWE-89 | SQL Injection        | GET /api/users/search (indirect)    | DETECTED              |
| CASE-M03 | Medium     | CWE-78 | Command Injection   | POST /api/diagnostic/run (ping)     | DETECTED              |
| CASE-H01 | Hard       | CWE-22 | Path Traversal       | GET /api/files/download (layered)    | DETECTED              |
| CASE-H02 | Hard       | CWE-90 | LDAP Injection       | POST /api/auth/login                 | DETECTED              |
| CASE-H03 | Hard       | CWE-643| XPath Injection      | GET /api/user/search                 | DETECTED              |

## Fixed Solutions

| Fixed Case      | Expected HWSEC Result |
|-----------------|-----------------------|
| E01-FIXED       | NOT_DETECTED          |
| E02-FIXED       | NOT_DETECTED          |
| E03-FIXED       | NOT_DETECTED          |
| M01-FIXED       | NOT_DETECTED          |
| M02-FIXED       | NOT_DETECTED          |
| M03-FIXED       | NOT_DETECTED          |
| H01-FIXED       | NOT_DETECTED          |
| H02-FIXED       | NOT_DETECTED          |
| H03-FIXED       | NOT_DETECTED          |
`);

writeFile('answer_key/witness_catalog.md', `# Witness Catalog

Exact inputs, commands, and expected security effects for each case.
This file is OUTSIDE benchmark_targets/ and must NOT be provided to HWSEC.

---

## CASE-E01 — Command Injection (Easy)
**Endpoint:** POST /api/diagnostic/ping
**Witness Input:** \`{"host": "127.0.0.1; touch /tmp/hwsec_e01_marker"}\`
**Expected Security Effect:** File /tmp/hwsec_e01_marker is created.

## CASE-E02 — SQL Injection (Easy)
**Endpoint:** GET /api/users/search?username=
**Witness Input:** \`username=' OR '1'='1\`
**Expected Security Effect:** All 4 user records returned (count > 1).

## CASE-E03 — Path Traversal (Easy)
**Endpoint:** GET /api/files/download?filename=
**Witness Input:** \`filename=../../../../etc/hostname\`
**Expected Security Effect:** Content of /etc/hostname returned.

## CASE-M01 — XSS (Medium)
**Endpoint:** GET /search?q=
**Witness Input:** \`q=<img src=x onerror=alert(1)>\`
**Expected Security Effect:** Raw \`<img src=x onerror=alert(1)>\` present in HTML response.

## CASE-M02 — SQL Injection (Medium)
**Endpoint:** GET /api/users/search?pattern=
**Witness Input:** \`pattern=' UNION SELECT id, username, email, role, department FROM users-- \`
**Expected Security Effect:** All 5 user records returned via UNION.

## CASE-M03 — Command Injection (Medium)
**Endpoint:** POST /api/diagnostic/run
**Witness Input:** \`{"target": "127.0.0.1; touch /tmp/hwsec_m03_marker", "tool": "ping"}\`
**Expected Security Effect:** File /tmp/hwsec_m03_marker created via ping tool.

## CASE-H01 — Path Traversal (Hard)
**Endpoint:** GET /api/files/download?filename=
**Witness Input:** \`filename=../../../../etc/hostname\`
**Expected Security Effect:** File outside storage directory returned.

## CASE-H02 — LDAP Injection (Hard)
**Endpoint:** POST /api/auth/login
**Witness Input:** \`{"username": "admin)(|(userPassword=*", "password": "anything"}\`
**Expected Security Effect:** Login succeeds despite wrong password (auth bypass).

## CASE-H03 — XPath Injection (Hard)
**Endpoint:** GET /api/user/search?username=
**Witness Input:** \`username=' or '1'='1\`
**Expected Security Effect:** First user record returned without exact username match.
`);

// ── SCRIPTS ──────────────────────────────────────────────────────────────────

writeFile('scripts/run_all_safe_checks.sh', `#!/bin/bash
set -e

echo "============================================"
echo "HWSEC Benchmark - All Safe Checks"
echo "============================================"
echo ""

BENCH_ROOT="\$(cd "\$(dirname "\$0")/.." && pwd)"
FAIL_COUNT=0
PASS_COUNT=0

run_case_tests() {
    local dir="\$1"
    local label="\$2"
    
    if [ ! -f "\$dir/test_app.py" ]; then
        echo "  [SKIP] No test_app.py in \$dir"
        return
    fi
    
    cd "\$dir"
    
    if python3 -m pytest test_app.py -v 2>&1; then
        echo "  [PASS] \$label"
        PASS_COUNT=\$((PASS_COUNT + 1))
    else
        echo "  [FAIL] \$label"
        FAIL_COUNT=\$((FAIL_COUNT + 1))
    fi
    cd "\$BENCH_ROOT"
}

echo "--- Vulnerable Targets ---"
echo ""
echo "EASY:"
for dir in "\$BENCH_ROOT"/benchmark_targets/easy/*/; do
    [ -d "\$dir" ] || continue
    name=\$(basename "\$dir")
    echo "  Testing: \$name"
    run_case_tests "\$dir" "\$name"
done

echo ""
echo "MEDIUM:"
for dir in "\$BENCH_ROOT"/benchmark_targets/medium/*/; do
    [ -d "\$dir" ] || continue
    name=\$(basename "\$dir")
    echo "  Testing: \$name"
    run_case_tests "\$dir" "\$name"
done

echo ""
echo "HARD:"
for dir in "\$BENCH_ROOT"/benchmark_targets/hard/*/; do
    [ -d "\$dir" ] || continue
    name=\$(basename "\$dir")
    echo "  Testing: \$name"
    run_case_tests "\$dir" "\$name"
done

echo ""
echo "--- Fixed Solutions ---"
echo ""
echo "EASY FIXED:"
for dir in "\$BENCH_ROOT"/solutions/easy/*/; do
    [ -d "\$dir" ] || continue
    name=\$(basename "\$dir")
    echo "  Testing: \$name"
    run_case_tests "\$dir" "\$name"
done

echo ""
echo "MEDIUM FIXED:"
for dir in "\$BENCH_ROOT"/solutions/medium/*/; do
    [ -d "\$dir" ] || continue
    name=\$(basename "\$dir")
    echo "  Testing: \$name"
    run_case_tests "\$dir" "\$name"
done

echo ""
echo "HARD FIXED:"
for dir in "\$BENCH_ROOT"/solutions/hard/*/; do
    [ -d "\$dir" ] || continue
    name=\$(basename "\$dir")
    echo "  Testing: \$name"
    run_case_tests "\$dir" "\$name"
done

echo ""
echo "============================================"
echo "Results: \$PASS_COUNT passed, \$FAIL_COUNT failed"
echo "============================================"

if [ "\$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
`);

writeFile('scripts/verify_structure.py', `#!/usr/bin/env python3
"""Verify benchmark directory structure and separation rules."""

import os
import sys
import json

BENCH_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ERRORS = []
WARNINGS = []


def check_exists(path, label):
    if not os.path.exists(path):
        ERRORS.append(f"Missing: {label} at {path}")
        return False
    return True


def check_no_answer_key_in_targets():
    targets = os.path.join(BENCH_ROOT, 'benchmark_targets')
    for root, dirs, files in os.walk(targets):
        for f in files:
            if 'answer_key' in f or 'witness' in f.lower() or 'FIX_NOTES' in f:
                ERRORS.append(f"Forbidden file in benchmark_targets: {os.path.join(root, f)}")
            if f.endswith('.py') and f != 'test_app.py':
                filepath = os.path.join(root, f)
                with open(filepath, 'r') as fh:
                    content = fh.read()
                    for marker in ['VULNERABLE=true', 'CWE-', 'intentionally vulnerable',
                                   'this is vulnerable', 'exploit_payload']:
                        if marker.lower() in content.lower():
                            ERRORS.append(f"Vulnerability marker '{marker}' in {filepath}")


def check_case_structure(case_dir, case_id, is_solution=False):
    required_files = ['app.py', 'requirements.txt', 'test_app.py', 'run.sh', 'README.md']
    if is_solution:
        required_files.append('FIX_NOTES.md')
    
    for f in required_files:
        path = os.path.join(case_dir, f)
        if not os.path.exists(path):
            ERRORS.append(f"Missing {f} in {case_dir}")


def check_all_cases():
    base = os.path.join(BENCH_ROOT, 'benchmark_targets')
    sol_base = os.path.join(BENCH_ROOT, 'solutions')
    
    cases = {
        'easy': ['CASE-E01', 'CASE-E02', 'CASE-E03'],
        'medium': ['CASE-M01', 'CASE-M02', 'CASE-M03'],
        'hard': ['CASE-H01', 'CASE-H02', 'CASE-H03'],
    }
    
    for level, case_ids in cases.items():
        for case_id in case_ids:
            target_dir = os.path.join(base, level)
            sol_dir = os.path.join(sol_base, level)
            
            found_target = False
            found_solution = False
            
            if os.path.isdir(target_dir):
                for d in os.listdir(target_dir):
                    if d.startswith(case_id):
                        check_case_structure(os.path.join(target_dir, d), case_id)
                        found_target = True
                        break
            
            if os.path.isdir(sol_dir):
                for d in os.listdir(sol_dir):
                    if d.startswith(case_id):
                        check_case_structure(os.path.join(sol_dir, d), case_id, is_solution=True)
                        found_solution = True
                        break
            
            if not found_target:
                ERRORS.append(f"Missing vulnerable case: {case_id} in {target_dir}")
            if not found_solution:
                ERRORS.append(f"Missing fixed solution: {case_id} in {sol_dir}")


def check_answer_key():
    ak = os.path.join(BENCH_ROOT, 'answer_key')
    check_exists(os.path.join(ak, 'benchmark_manifest.json'), 'benchmark_manifest.json')
    check_exists(os.path.join(ak, 'expected_findings.md'), 'expected_findings.md')
    check_exists(os.path.join(ak, 'witness_catalog.md'), 'witness_catalog.md')


def check_scripts():
    check_exists(os.path.join(BENCH_ROOT, 'scripts', 'run_all_safe_checks.sh'), 'run_all_safe_checks.sh')
    check_exists(os.path.join(BENCH_ROOT, 'scripts', 'verify_structure.py'), 'verify_structure.py')


def main():
    check_exists(os.path.join(BENCH_ROOT, 'benchmark_targets'), 'benchmark_targets/')
    check_exists(os.path.join(BENCH_ROOT, 'solutions'), 'solutions/')
    check_exists(os.path.join(BENCH_ROOT, 'answer_key'), 'answer_key/')
    check_exists(os.path.join(BENCH_ROOT, 'scripts'), 'scripts/')
    check_exists(os.path.join(BENCH_ROOT, 'README.md'), 'root README.md')
    
    check_no_answer_key_in_targets()
    check_all_cases()
    check_answer_key()
    check_scripts()
    
    print("=== Structure Verification ===")
    if ERRORS:
        print(f"\\nERRORS ({len(ERRORS)}):")
        for e in ERRORS:
            print(f"  [ERROR] {e}")
    
    if WARNINGS:
        print(f"\\nWARNINGS ({len(WARNINGS)}):")
        for w in WARNINGS:
            print(f"  [WARN]  {w}")
    
    if not ERRORS:
        print("\\n[PASS] All structure checks passed.")
        sys.exit(0)
    else:
        print(f"\\n[FAIL] {len(ERRORS)} error(s) found.")
        sys.exit(1)


if __name__ == '__main__':
    main()
`);

console.log('[+] Benchmark generation complete!');
