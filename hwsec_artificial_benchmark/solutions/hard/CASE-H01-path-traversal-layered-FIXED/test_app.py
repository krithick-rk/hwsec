import os
import pytest
from app import app, file_service


@pytest.fixture
def client():
    file_service.init_storage()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_download(client):
    response = client.get('/api/files/download?filename=readme.txt')
    assert response.status_code == 200
    data = response.get_json()
    assert 'Welcome' in data['content']


def test_regression_traversal_blocked(client):
    response = client.get('/api/files/download?filename=../../../../etc/hostname')
    assert response.status_code == 403


def test_benign_still_works(client):
    response = client.get('/api/files/download?filename=notes.txt')
    assert response.status_code == 200


def test_preview_traversal_blocked(client):
    response = client.get('/api/files/preview?filename=../../../../etc/hostname')
    assert response.status_code == 403
