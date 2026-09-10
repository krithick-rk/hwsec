from flask import Flask, request, jsonify
from services.auth_service import AuthService
from config import Config

app = Flask(__name__)
config = Config()
auth_service = AuthService(config)


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'username and password are required'}), 400

    result = auth_service.authenticate(username, password)
    if result['authenticated']:
        return jsonify({'status': 'success', 'user': result['user']})
    return jsonify({'status': 'failed', 'message': 'invalid credentials'}), 401


@app.route('/api/auth/lookup', methods=['GET'])
def lookup_user():
    username = request.args.get('username', '')
    if not username:
        return jsonify({'error': 'username parameter is required'}), 400

    result = auth_service.lookup_user(username)
    if result:
        return jsonify({'found': True, 'user': result})
    return jsonify({'found': False})


@app.route('/api/auth/verify/<int:user_id>', methods=['GET'])
def verify_user(user_id):
    result = auth_service.verify_by_id(user_id)
    if result:
        return jsonify({'valid': True, 'user': result})
    return jsonify({'valid': False}), 404


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5202, debug=True)
