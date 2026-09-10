from flask import Flask, request, jsonify
from services.user_service import UserService
from config import Config

app = Flask(__name__)
config = Config()
user_service = UserService(config)


@app.route('/api/user/search', methods=['GET'])
def search_user():
    username = request.args.get('username', '')
    if not username:
        return jsonify({'error': 'username parameter is required'}), 400
    result = user_service.find_user(username)
    if result:
        return jsonify({'found': True, 'user': result})
    return jsonify({'found': False})


@app.route('/api/user/search_by_email', methods=['GET'])
def search_by_email():
    email = request.args.get('email', '')
    if not email:
        return jsonify({'error': 'email parameter is required'}), 400
    result = user_service.find_user_by_email(email)
    if result:
        return jsonify({'found': True, 'user': result})
    return jsonify({'found': False})


@app.route('/api/user/by_id/<int:user_id>', methods=['GET'])
def get_by_id(user_id):
    result = user_service.get_user_by_id(user_id)
    if result:
        return jsonify({'found': True, 'user': result})
    return jsonify({'found': False}), 404


@app.route('/api/user/list', methods=['GET'])
def list_users():
    users = user_service.list_all_users()
    return jsonify({'users': users, 'count': len(users)})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5203, debug=True)
