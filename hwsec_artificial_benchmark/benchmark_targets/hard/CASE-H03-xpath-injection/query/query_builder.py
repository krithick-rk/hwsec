class QueryBuilder:
    def build_username_query(self, username):
        return f"//user[name='{username}']"

    def build_email_query(self, email):
        return f"//user[email='{email}']"

    def build_id_query(self, user_id):
        return f"//user[@id='{user_id}']"
