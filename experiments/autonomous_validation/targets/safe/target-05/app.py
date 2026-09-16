import sys
import re
import subprocess

HOST_PATTERN = re.compile(r'^[a-zA-Z0-9.-]+$')

def run_diagnostic(host):
    if not HOST_PATTERN.match(host) or len(host) > 255:
        print(f'[BLOCKED] Invalid host format: {host}')
        sys.exit(1)
    # Remediated: structured array without shell=True
    return subprocess.run(['ping', '-c', '1', '-W', '2', host], capture_output=True, text=True)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        run_diagnostic(sys.argv[1])
    else:
        from flask import Flask, request, jsonify
        app = Flask(__name__)
        @app.route('/api/diagnostic/ping', methods=['POST'])
        def ping_host():
            host = request.json.get('host', '')
            res = run_diagnostic(host)
            if res is None:
                return jsonify({'error': 'invalid host format'}), 400
            return jsonify({'host': host})
        app.run(host='127.0.0.1', port=5001)
