from flask import Flask, request, render_template, jsonify
from services.search_service import SearchService

app = Flask(__name__)
app.template_folder = 'templates'

search_service = SearchService()


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    results = search_service.search_products(query)
    return render_template('search.html', query=query, results=results)


@app.route('/api/search', methods=['GET'])
def api_search():
    query = request.args.get('q', '')
    results = search_service.search_products(query)
    return jsonify({'query': query, 'results': results, 'count': len(results)})


@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = search_service.get_product(product_id)
    if product is None:
        return jsonify({'error': 'product not found'}), 404
    return jsonify(product)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5101, debug=True)
