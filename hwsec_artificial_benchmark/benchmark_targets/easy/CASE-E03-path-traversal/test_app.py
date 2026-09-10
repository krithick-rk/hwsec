import os
import pytest
from app import app, FILES_DIR


@pytest.fixture
def client():
    os.makedirs(FILES_DIR, exist_ok=True)
    for name, content in [('hello.txt', 'Hello World!\n'), ('info.txt', 'Sample info file.\n')]:
        with open(os.path.join(FILES_DIR, name), 'w') as f:
            f.write(content)
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_download(client):
    response = client.get('/api/files/download?filename=hello.txt')
    assert response.status_code == 200
    data = response.get_json()
    assert 'Hello World' in data['content']


def test_list_files(client):
    response = client.get('/api/files/list')
    assert response.status_code == 200
    data = response.get_json()
    assert 'hello.txt' in data['files']


def test_special_input_handling(client):
    response = client.get('/api/files/download?filename=../../../../etc/hostname')
    assert response.status_code == 200
    data = response.get_json()
    assert data['content'] != '', 'Expected file content from special path'


def test_benign_no_traversal(client):
    response = client.get('/api/files/download?filename=hello.txt')
    assert response.status_code == 200
    data = response.get_json()
    assert data['content'] == 'Hello World!\n'
