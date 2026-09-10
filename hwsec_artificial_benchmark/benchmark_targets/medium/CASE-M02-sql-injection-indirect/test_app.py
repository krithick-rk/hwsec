import pytest
from app import app, db


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_search(client):
    response = client.get('/api/users/search?pattern=ali')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1
    assert data['users'][0]['username'] == 'alice'


def test_search_by_role(client):
    response = client.get('/api/users/by_role/user')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 3


def test_special_input_handling(client):
    response = client.get("/api/users/search?pattern=' UNION SELECT id, username, email, role, department FROM users-- ")
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] > 1, 'Expected multiple results from special input'


def test_benign_single_result(client):
    response = client.get('/api/users/search?pattern=admin')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1


def test_get_user_by_id(client):
    response = client.get('/api/users/1')
    assert response.status_code == 200
    data = response.get_json()
    assert data['username'] == 'admin'
