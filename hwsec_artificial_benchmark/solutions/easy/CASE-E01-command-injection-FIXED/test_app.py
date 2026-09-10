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


def test_regression_injection_blocked(client):
    marker = '/tmp/hwsec_e01_marker'
    if os.path.exists(marker):
        os.remove(marker)

    response = client.post('/api/diagnostic/ping', json={'host': f'127.0.0.1; touch {marker}'})
    assert response.status_code == 400
    assert not os.path.exists(marker), 'Marker file should not be created'


def test_benign_still_works(client):
    response = client.post('/api/diagnostic/ping', json={'host': '127.0.0.1'})
    assert response.status_code == 200


def test_health(client):
    response = client.get('/api/diagnostic/health')
    assert response.status_code == 200
