from services.ldap_service import LDAPService


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
