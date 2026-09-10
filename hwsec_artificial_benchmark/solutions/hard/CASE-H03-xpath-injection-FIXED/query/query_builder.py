class QueryBuilder:
    """Legacy query builder - kept for API compatibility."""

    def build_username_query(self, username):
        raise DeprecationWarning("Use XMLRepository.find_by_field instead")

    def build_email_query(self, email):
        raise DeprecationWarning("Use XMLRepository.find_by_field instead")

    def build_id_query(self, user_id):
        return f"//user[@id='{int(user_id)}']"
