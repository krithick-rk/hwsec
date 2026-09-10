from repositories.ldap_repository import MockLDAPRepository


class LDAPService:
    def __init__(self, config):
        self.config = config
        self.repository = MockLDAPRepository()

    def search(self, filter_str):
        return self.repository.search(
            self.config.LDAP_BASE_DN,
            filter_str
        )
