import sqlite3


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
