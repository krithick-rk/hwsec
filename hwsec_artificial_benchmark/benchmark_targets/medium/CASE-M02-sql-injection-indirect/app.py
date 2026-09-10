from flask import Flask, request, jsonify
from services.user_service import UserService
from database import init_db

app = Flask(__name__)

db = init_db()
user_service = UserService(db)


@app.route('/api/users/search', methods=['GET'])
def search_users():
    pattern = request.args.get('pattern', '')
    if not pattern:
        return jsonify({'error': 'pattern parameter is required'}), 400
    users = user_service.find_users_by_pattern(pattern)
    return jsonify({'users': users, 'count': len(users)})


@app.route('/api/users/by_role/<role>', methods=['GET'])
def get_users_by_role(role):
    users = user_service.find_users_by_role(role)
    return jsonify({'users': users, 'count': len(users)})


@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = user_service.get_user_by_id(user_id)
    if user is None:
        return jsonify({'error': 'user not found'}), 404
    return jsonify(user)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5102, debug=True)
