# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 5

from threatintel import create_app
from threatintel.fetch import fetch_kev, fetch_nvd
from datetime import datetime

def test_secret_key_default_is_not_the_tutorial_value(tmp_path):
    app = create_app({"DATABASE": str(tmp_path / "t.sqlite")})
    key = app.config["SECRET_KEY"]
    assert key != "dev" and len(key) >= 32


def test_secret_key_default_differs_between_apps(tmp_path):
    a = create_app({"DATABASE": str(tmp_path / "a.sqlite")})
    b = create_app({"DATABASE": str(tmp_path / "b.sqlite")})
    assert a.config["SECRET_KEY"] != b.config["SECRET_KEY"]


def test_secret_key_can_be_set_from_the_environment(tmp_path, monkeypatch):
    key = "env-key-" + "x" * 32
    monkeypatch.setenv("THREATINTEL_SECRET_KEY", key)
    app = create_app({"DATABASE": str(tmp_path / "t.sqlite")})
    assert app.config["SECRET_KEY"] == key

def test_default_fetchers_and_clock_are_the_real_ones(tmp_path):
    app = create_app({"DATABASE": str(tmp_path / "t.sqlite")})
    assert app.config["KEV_FETCHER"] is fetch_kev
    assert app.config["NVD_FETCHER"] is fetch_nvd
    now = app.config["CLOCK"]()
    assert isinstance(now, datetime) and now.tzinfo is not None
