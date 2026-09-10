class UserRepository:
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
