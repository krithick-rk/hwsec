from repositories.xml_repository import XMLRepository
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
