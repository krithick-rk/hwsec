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


def test_regression_injection_blocked(client):
    response = client.get("/api/users/search?pattern=' UNION SELECT id, username, email, role, department FROM users-- ")
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 0


def test_benign_still_works(client):
    response = client.get('/api/users/search?pattern=admin')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1
