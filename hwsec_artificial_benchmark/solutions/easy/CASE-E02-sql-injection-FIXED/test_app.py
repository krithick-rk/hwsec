import pytest
from app import app, db


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_search(client):
    response = client.get('/api/users/search?username=alice')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1
    assert data['users'][0]['username'] == 'alice'


def test_regression_injection_blocked(client):
    response = client.get("/api/users/search?username=' OR '1'='1")
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 0, 'Injection should return no results'


def test_benign_single_result(client):
    response = client.get('/api/users/search?username=admin')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1
