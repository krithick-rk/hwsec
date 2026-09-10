from flask import Flask, request, jsonify
import subprocess
import re

app = Flask(__name__)

HOST_PATTERN = re.compile(r'^[a-zA-Z0-9.-]+$')


@app.route('/api/diagnostic/ping', methods=['POST'])
def ping_host():
    host = request.json.get('host', '')
    if not host:
        return jsonify({'error': 'host parameter is required'}), 400

    if not HOST_PATTERN.match(host) or len(host) > 255:
        return jsonify({'error': 'invalid host format'}), 400

    result = subprocess.run(
        ['ping', '-c', '1', '-W', '2', host],
        capture_output=True, text=True, timeout=10
    )

    return jsonify({
        'host': host,
        'output': result.stdout,
        'error': result.stderr,
        'returncode': result.returncode
    })


@app.route('/api/diagnostic/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)
