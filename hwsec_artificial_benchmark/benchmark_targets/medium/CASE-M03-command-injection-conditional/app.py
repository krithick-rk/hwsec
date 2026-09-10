from flask import Flask, request, jsonify
from services.diagnostic_service import DiagnosticService

app = Flask(__name__)
diag_service = DiagnosticService()


@app.route('/api/diagnostic/run', methods=['POST'])
def run_diagnostic():
    data = request.json or {}
    target = data.get('target', '')
    tool = data.get('tool', 'ping')

    if not target:
        return jsonify({'error': 'target parameter is required'}), 400

    result = diag_service.run_tool(target, tool)
    return jsonify(result)


@app.route('/api/diagnostic/tools', methods=['GET'])
def list_tools():
    return jsonify({'tools': diag_service.available_tools()})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5103, debug=True)
