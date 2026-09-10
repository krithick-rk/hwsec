from repositories.user_repository import UserRepository


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
