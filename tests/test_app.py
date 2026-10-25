import os
import pytest
from app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_health(client):
    resp = client.get('/healthz')
    assert resp.status_code == 200
    assert resp.get_json()['status'] == 'ok'


def test_login_page(client):
    resp = client.get('/login')
    assert resp.status_code == 200


def test_dashboard_requires_login(client):
    resp = client.get('/dashboard')
    assert resp.status_code == 302


def test_invalid_upload_filename(client):
    client.post('/login', data={'username': 'admin', 'password': 'AdminPass123!'})
    resp = client.post('/upload-script', data={'bot_id': '1', 'script': (b'print(123)', '../bad.py')})
    assert resp.status_code in (200, 400)
