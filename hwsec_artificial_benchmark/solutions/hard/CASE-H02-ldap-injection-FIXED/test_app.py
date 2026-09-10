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


def test_regression_injection_blocked(client):
    response = client.post('/api/auth/login', json={
        'username': 'admin)(|(userPassword=*',
        'password': 'anything'
    })
    assert response.status_code == 401


def test_benign_login_still_works(client):
    response = client.post('/api/auth/login', json={'username': 'user1', 'password': 'pass1'})
    assert response.status_code == 200


def test_wrong_password(client):
    response = client.post('/api/auth/login', json={'username': 'admin', 'password': 'wrong'})
    assert response.status_code == 401
