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


def test_regression_injection_blocked(client):
    response = client.get("/api/user/search?username=' or '1'='1")
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is False


def test_benign_still_works(client):
    response = client.get('/api/user/search?username=admin')
    assert response.status_code == 200
    data = response.get_json()
    assert data['found'] is True


def test_list_users(client):
    response = client.get('/api/user/list')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 4
