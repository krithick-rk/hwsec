from flask import Flask, request, jsonify
from services.file_service import FileService
from config import Config

app = Flask(__name__)
config = Config()
file_service = FileService(config)


@app.route('/api/files/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename', '')
    if not filename:
        return jsonify({'error': 'filename parameter is required'}), 400
    result = file_service.read_file(filename)
    if result is None:
        return jsonify({'error': 'file not found'}), 404
    if isinstance(result, dict) and 'error' in result:
        return jsonify(result), 403
    return jsonify({'filename': filename, 'content': result})


@app.route('/api/files/preview', methods=['GET'])
def preview_file():
    filename = request.args.get('filename', '')
    if not filename:
        return jsonify({'error': 'filename parameter is required'}), 400
    result = file_service.preview_file(filename)
    if result is None:
        return jsonify({'error': 'file not found'}), 404
    if isinstance(result, dict) and 'error' in result:
        return jsonify(result), 403
    return jsonify({'filename': filename, 'content': result, 'preview': True})


@app.route('/api/files/list', methods=['GET'])
def list_files():
    files = file_service.list_files()
    return jsonify({'files': files})


if __name__ == '__main__':
    file_service.init_storage()
    app.run(host='127.0.0.1', port=5201, debug=True)
