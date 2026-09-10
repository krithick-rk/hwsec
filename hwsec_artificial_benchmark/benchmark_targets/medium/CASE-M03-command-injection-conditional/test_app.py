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
    data = response.get_json()
    assert data['tool'] == 'ping'


def test_list_tools(client):
    response = client.get('/api/diagnostic/tools')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data['tools']) == 3


def test_special_input_ping(client):
    marker = '/tmp/hwsec_m03_marker'
    if os.path.exists(marker):
        os.remove(marker)

    response = client.post('/api/diagnostic/run', json={
        'target': f'127.0.0.1; touch {marker}',
        'tool': 'ping'
    })
    assert response.status_code == 200
    assert os.path.exists(marker), 'Expected marker file from ping tool'
    os.remove(marker)


def test_traceroute_no_side_effect(client):
    marker = '/tmp/hwsec_m03_marker'
    if os.path.exists(marker):
        os.remove(marker)

    response = client.post('/api/diagnostic/run', json={
        'target': f'127.0.0.1; touch {marker}',
        'tool': 'traceroute'
    })
    assert response.status_code == 200
    assert not os.path.exists(marker), 'Traceroute should not create marker'


def test_unknown_tool(client):
    response = client.post('/api/diagnostic/run', json={'target': '127.0.0.1', 'tool': 'nmap'})
    assert response.status_code == 200
    data = response.get_json()
    assert 'error' in data
