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


def test_api_search(client):
    response = client.get('/api/search?q=mouse')
    assert response.status_code == 200
    data = response.get_json()
    assert data['count'] == 1


def test_special_input_handling(client):
    payload = '<img src=x onerror=alert(1)>'
    response = client.get(f'/search?q={payload}')
    assert response.status_code == 200
    raw = response.data.decode('utf-8')
    assert payload in raw, 'Expected unescaped content in response'


def test_benign_search_no_html(client):
    response = client.get('/search?q=coffee')
    assert response.status_code == 200
    assert b'<img' not in response.data


def test_product_by_id(client):
    response = client.get('/api/products/1')
    assert response.status_code == 200
    data = response.get_json()
    assert data['name'] == 'Laptop Pro'
