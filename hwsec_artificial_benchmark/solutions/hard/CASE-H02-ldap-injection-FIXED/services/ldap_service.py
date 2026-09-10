import re
from repositories.ldap_repository import MockLDAPRepository


class LDAPService:
    SAFE_CHARS = re.compile(r'^[a-zA-Z0-9._\-@]+$')

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
