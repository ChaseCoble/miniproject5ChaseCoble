# INF601: Advanced Programming with Pythong
# Chase Coble
# Mini Project 5

import json
from pathlib import Path
import pytest

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
