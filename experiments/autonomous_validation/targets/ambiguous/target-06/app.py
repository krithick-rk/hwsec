import sys
import logging

logging.basicConfig(level=logging.INFO)

def update_profile(username, bio):
    logging.info("Profile updated for user: %s (bio length: %d)", username, len(bio))
    return {'status': 'updated', 'user': username, 'bio_summary': bio[:20] if bio else ''}

if __name__ == '__main__':
    if len(sys.argv) > 1:
        update_profile(sys.argv[1], "Sample bio text")
    else:
        from flask import Flask, request, jsonify
        app = Flask(__name__)
        @app.route('/api/profile/update', methods=['POST'])
        def route_update():
            u = request.json.get('username', '')
            b = request.json.get('bio', '')
            return jsonify(update_profile(u, b))
        app.run(host='127.0.0.1', port=5002)
