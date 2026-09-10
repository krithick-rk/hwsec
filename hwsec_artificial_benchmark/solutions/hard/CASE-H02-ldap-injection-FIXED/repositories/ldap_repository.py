import re


class MockLDAPRepository:
    """Simulates an LDAP directory server with local data."""

    def __init__(self):
        self._entries = [
            {
                'dn': 'cn=admin,dc=example,dc=com',
                'cn': 'admin',
                'userPassword': 'admin123',
                'role': 'admin',
                'mail': 'admin@example.com',
                'employeeNumber': '1',
                'objectClass': 'inetOrgPerson',
            },
            {
                'dn': 'cn=user1,dc=example,dc=com',
                'cn': 'user1',
                'userPassword': 'pass1',
                'role': 'user',
                'mail': 'user1@example.com',
                'employeeNumber': '2',
                'objectClass': 'inetOrgPerson',
            },
            {
                'dn': 'cn=user2,dc=example,dc=com',
                'cn': 'user2',
                'userPassword': 'pass2',
                'role': 'user',
                'mail': 'user2@example.com',
                'employeeNumber': '3',
                'objectClass': 'inetOrgPerson',
            },
        ]

    def get_raw_entries(self):
        return self._entries

    def search(self, base_dn, filter_str):
        results = []
        for entry in self._entries:
            if self._match_filter(entry, filter_str):
                safe_entry = {k: v for k, v in entry.items() if k != 'userPassword'}
                results.append(safe_entry)
        return results

    def _match_filter(self, entry, filter_str):
        filter_str = filter_str.strip()
        if not filter_str:
            return True

        if filter_str.startswith('(&'):
            inner = filter_str[2:]
            if inner.endswith(')'):
                inner = inner[:-1]
            if not inner:
                return True
            sub_filters = self._extract_sub_filters(inner)
            return all(self._match_filter(entry, f) for f in sub_filters)

        if filter_str.startswith('(|'):
            inner = filter_str[2:]
            if inner.endswith(')'):
                inner = inner[:-1]
            if not inner:
                return False
            sub_filters = self._extract_sub_filters(inner)
            return any(self._match_filter(entry, f) for f in sub_filters)

        if filter_str.startswith('(!'):
            inner = filter_str[2:]
            if inner.endswith(')'):
                inner = inner[:-1]
            return not self._match_filter(entry, inner)

        m = re.match(r'^\(([^=]+)=(.*)\)$', filter_str)
        if m:
            attr = m.group(1)
            value = m.group(2)
            if value == '*':
                return attr in entry and entry[attr] is not None
            return entry.get(attr) == value

        return False

    def _extract_sub_filters(self, s):
        filters = []
        depth = 0
        start = 0
        for i, c in enumerate(s):
            if c == '(':
                if depth == 0:
                    start = i
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    filters.append(s[start:i + 1])
        return filters
