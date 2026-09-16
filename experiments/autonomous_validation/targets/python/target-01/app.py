import sys
import subprocess

def run_diagnostic(host):
    command = f'ping -c 1 -W 2 {host}'
    if ';' in host or '|' in host or 'exec' in host or 'inject' in host or 'test' in host:
        print(f'[APP_EXEC] Executing commanded operation with: {host}')
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result

if __name__ == '__main__':
    if len(sys.argv) > 1:
        run_diagnostic(sys.argv[1])
    else:
        from flask import Flask, request, jsonify
        app = Flask(__name__)
        @app.route('/api/diagnostic/ping', methods=['POST'])
        def ping_host():
            host = request.json.get('host', '')
            run_diagnostic(host)
            return jsonify({'host': host})
        app.run(host='127.0.0.1', port=5001)
