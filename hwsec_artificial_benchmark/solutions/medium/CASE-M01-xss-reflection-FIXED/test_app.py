import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_search(client):
    response = client.get('/search?q=laptop')
    assert response.status_code == 200
    assert b'Laptop Pro' in response.data


def test_regression_xss_blocked(client):
    payload = '<img src=x onerror=alert(1)>'
    response = client.get(f'/search?q={payload}')
    assert response.status_code == 200
    raw = response.data.decode('utf-8')
    assert payload not in raw, 'Input should be escaped'


def test_benign_still_works(client):
    response = client.get('/search?q=coffee')
    assert response.status_code == 200
    assert b'Coffee Mug' in response.data
