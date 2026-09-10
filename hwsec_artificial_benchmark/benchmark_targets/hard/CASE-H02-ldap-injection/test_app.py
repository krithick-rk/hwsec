import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_login(client):
    response = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin123'})
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'success'


def test_wrong_password(client):
    response = client.post('/api/auth/login', json={'username': 'admin', 'password': 'wrong'})
    assert response.status_code == 401


def test_lookup_user(client):
    response = client.get('/api/auth/lookup?username=admin')
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is True


def test_special_input_auth(client):
    response = client.post('/api/auth/login', json={
        'username': 'admin)(|(userPassword=*',
        'password': 'anything'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'success', 'Expected auth bypass with special input'


def test_verify_by_id(client):
    response = client.get('/api/auth/verify/1')
    assert response.status_code == 200
    data = response.get_json()
    assert data['valid'] is True


def test_verify_wrong_id(client):
    response = client.get('/api/auth/verify/999')
    assert response.status_code == 404
