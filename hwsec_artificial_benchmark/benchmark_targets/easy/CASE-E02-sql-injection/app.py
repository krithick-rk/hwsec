from flask import Flask, request, jsonify
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
