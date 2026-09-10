from flask import Flask, request, jsonify, send_file
import os

app = Flask(__name__)

FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')


@app.route('/api/files/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename', '')
    if not filename:
        return jsonify({'error': 'filename parameter is required'}), 400

    filepath = os.path.join(FILES_DIR, filename)

    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return jsonify({'filename': filename, 'content': content})
    except FileNotFoundError:
        return jsonify({'error': 'file not found'}), 404
    except IsADirectoryError:
        return jsonify({'error': 'path is a directory'}), 400


@app.route('/api/files/list', methods=['GET'])
def list_files():
    files = os.listdir(FILES_DIR)
    return jsonify({'files': files})


if __name__ == '__main__':
    os.makedirs(FILES_DIR, exist_ok=True)
    for name, content in [('hello.txt', 'Hello World!\n'), ('info.txt', 'Sample info file.\n')]:
        with open(os.path.join(FILES_DIR, name), 'w') as f:
            f.write(content)
    app.run(host='127.0.0.1', port=5003, debug=True)
