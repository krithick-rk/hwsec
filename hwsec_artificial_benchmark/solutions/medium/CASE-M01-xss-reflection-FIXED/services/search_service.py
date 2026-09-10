class SearchService:
    def __init__(self):
        self._products = [
            {'id': 1, 'name': 'Laptop Pro', 'price': 1299.99, 'category': 'electronics'},
            {'id': 2, 'name': 'Wireless Mouse', 'price': 29.99, 'category': 'electronics'},
            {'id': 3, 'name': 'Coffee Mug', 'price': 12.50, 'category': 'kitchen'},
            {'id': 4, 'name': 'Notebook', 'price': 4.99, 'category': 'office'},
            {'id': 5, 'name': 'Desk Lamp', 'price': 45.00, 'category': 'office'},
        ]

    def search_products(self, query):
        if not query:
            return self._products[:5]
        lowered = query.lower()
        return [p for p in self._products if lowered in p['name'].lower()]

    def get_product(self, product_id):
        for p in self._products:
            if p['id'] == product_id:
                return p
        return None
