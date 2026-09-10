from repositories.xml_repository import XMLRepository


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
