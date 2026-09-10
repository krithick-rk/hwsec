import os
import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_ping(client):
    response = client.post('/api/diagnostic/ping', json={'host': '127.0.0.1'})
    assert response.status_code == 200
    data = response.get_json()
    assert data['host'] == '127.0.0.1'


def test_missing_host(client):
    response = client.post('/api/diagnostic/ping', json={})
    assert response.status_code == 400


def test_special_input_handling(client):
    marker = '/tmp/hwsec_e01_marker'
    if os.path.exists(marker):
        os.remove(marker)

    response = client.post('/api/diagnostic/ping', json={'host': f'127.0.0.1; touch {marker}'})
    assert response.status_code == 200

    assert os.path.exists(marker), 'Expected marker file to be created'
    os.remove(marker)


def test_benign_no_side_effect(client):
    marker = '/tmp/hwsec_e01_marker'
    if os.path.exists(marker):
        os.remove(marker)

    response = client.post('/api/diagnostic/ping', json={'host': '127.0.0.1'})
    assert response.status_code == 200
    assert not os.path.exists(marker)


def test_health(client):
    response = client.get('/api/diagnostic/health')
    assert response.status_code == 200
