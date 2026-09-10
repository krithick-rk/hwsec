import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_search(client):
    response = client.get('/api/user/search?username=alice')
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is True
    assert data['user']['name'] == 'alice'


def test_search_not_found(client):
    response = client.get('/api/user/search?username=nonexistent')
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is False


def test_special_input_search(client):
    response = client.get("/api/user/search?username=' or '1'='1")
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is True
    assert 'name' in data['user'], 'Expected user data from special input'


def test_by_id(client):
    response = client.get('/api/user/by_id/1')
    assert response.status_code == 200
    data = response.get_json()
    assert data['user']['name'] == 'admin'


def test_by_id_not_found(client):
    response = client.get('/api/user/by_id/999')
    assert response.status_code == 404


def test_list_users(client):
    response = client.get('/api/user/list')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 4


def test_search_by_email(client):
    response = client.get('/api/user/search_by_email?email=alice@example.com')
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is True
