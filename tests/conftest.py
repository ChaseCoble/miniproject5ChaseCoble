# INF601: Advanced Programming with Pythong
# Chase Coble
# Mini Project 5

import json
from pathlib import Path
import pytest
import socket
from datetime import datetime, timezone

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

class FakeClock:
    def __init__(self):
        self.now = datetime(2099, 6, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, delta):
        self.now += delta


class FakeFetchers:
    """Stands in for fetch_kev / fetch_nvd. Records calls and can be told to fail."""

    def __init__(self, kev_feed, nvd_doc_for):
        self.kev_feed = kev_feed
        self.nvd_doc_for = nvd_doc_for
        self.kev_error = None
        self.nvd_error = None
        self.kev_calls = 0
        self.nvd_calls = []

    def kev(self):
        self.kev_calls += 1
        if self.kev_error is not None:
            raise self.kev_error
        return self.kev_feed

    def nvd(self, cve_id):
        self.nvd_calls.append(cve_id)
        if self.nvd_error is not None:
            raise self.nvd_error
        return self.nvd_doc_for(cve_id)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def fetchers(app, clock, kev_entry, load_fixture):
    def nvd_doc_for(cve_id):
        doc = load_fixture("nvd_undergoing_analysis.json")
        doc["vulnerabilities"][0]["cve"]["id"] = cve_id
        return doc

    feed = {"vulnerabilities": [kev_entry(cveID=f"CVE-2099-{i:04d}") for i in (1, 2, 3)]}
    fake = FakeFetchers(feed, nvd_doc_for)
    app.config.update(KEV_FETCHER=fake.kev, NVD_FETCHER=fake.nvd, CLOCK=clock)
    return fake


@pytest.fixture
def seed(app):
    from threatintel.db import get_db, upsert_kev
    from threatintel.sources import parse_kev

    def _seed(entries):
        with app.app_context():
            upsert_kev(get_db(), parse_kev({"vulnerabilities": entries}))
    return _seed


def _logged_in_client(app, username):
    client = app.test_client()
    actions = AuthActions(client)
    actions.register(username, "test-pass-123")
    actions.login(username, "test-pass-123")
    return client


@pytest.fixture
def alice(app):
    return _logged_in_client(app, "alice")


@pytest.fixture
def bob(app):
    return _logged_in_client(app, "bob")
