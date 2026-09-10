import os
import pytest
from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_normal_ping(client):
    response = client.post('/api/diagnostic/run', json={'target': '127.0.0.1', 'tool': 'ping'})
    assert response.status_code == 200


def test_regression_injection_blocked(client):
    marker = '/tmp/hwsec_m03_marker'
    if os.path.exists(marker):
        os.remove(marker)

    response = client.post('/api/diagnostic/run', json={
        'target': f'127.0.0.1; touch {marker}',
        'tool': 'ping'
    })
    assert response.status_code == 400
    assert not os.path.exists(marker)


def test_benign_still_works(client):
    response = client.post('/api/diagnostic/run', json={'target': '127.0.0.1', 'tool': 'ping'})
    assert response.status_code == 200
