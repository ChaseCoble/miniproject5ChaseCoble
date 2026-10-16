# INF601: Advanced Programming with Pythong
# Chase Coble
# Mini Project 5

import json
from pathlib import Path
import pytest
import socket

FIXTURES = Path(__file__).parent / "fixtures"

@pytest.fixture
def load_fixture():
    def _load(name):
        return json.loads((FIXTURES / name).read_text())
    return _load

@pytest.fixture
def kev_entry():
    def _make(**overrides):
        entry = {
            "cveID": "CVE-2099-0001",
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": "Acme Widget Test Vulnerability",
            "shortDescription": "Fake entry for tests.",
            "dateAdded": "2099-01-01",
            "dueDate": "2099-01-22",
            "knownRansomwareCampaignUse": "Unknown",
            "cwes": [],
            "notes": "",
        }
        entry.update(overrides)
        return entry
    return _make

@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    # hard control: any real connection attempt in any test fails loudly
    def refuse(*args, **kwargs):
        raise RuntimeError("tests must not touch the network")
    monkeypatch.setattr(socket.socket, "connect", refuse)


def _test_config(tmp_path):
    return {
        "TESTING": True,
        "SECRET_KEY": "test-only-not-a-secret",
        "DATABASE": str(tmp_path / "test.sqlite"),
    }


@pytest.fixture
def blank_app(tmp_path):
    from threatintel import create_app
    return create_app(_test_config(tmp_path))


@pytest.fixture
def app(blank_app):
    from threatintel.db import init_db
    with blank_app.app_context():
        init_db()
    return blank_app


@pytest.fixture
def db(app):
    from threatintel.db import get_db
    with app.app_context():
        yield get_db()

class AuthActions:
    def __init__(self, client):
        self._client = client

    def register(self, username="alice", password="test-pass-123"):
        return self._client.post("/auth/register", data={"username": username, "password": password})

    def login(self, username="alice", password="test-pass-123"):
        return self._client.post("/auth/login", data={"username": username, "password": password})

    def logout(self):
        return self._client.post("/auth/logout")


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth(client):
    return AuthActions(client)
