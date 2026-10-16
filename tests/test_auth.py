# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 5

from urllib.parse import urlparse

import pytest
from flask import g, session
from werkzeug.security import check_password_hash

from threatintel.db import get_db

PW = "test-pass-123"


def user_rows(app):
    with app.app_context():
        return [dict(r) for r in get_db().execute("SELECT * FROM user").fetchall()]


# ---------- register ----------

def test_register_page_loads(client):
    assert client.get("/auth/register").status_code == 200


def test_register_creates_user_and_redirects_to_login(auth, app):
    response = auth.register("alice", PW)
    assert response.status_code == 302
    assert urlparse(response.headers["Location"]).path == "/auth/login"
    assert [u["username"] for u in user_rows(app)] == ["alice"]


def test_register_stores_a_hash_not_the_password(auth, app):
    auth.register("alice", PW)
    stored = user_rows(app)[0]["password"]
    assert stored != PW and PW not in stored
    assert check_password_hash(stored, PW)
    assert not check_password_hash(stored, PW + "x")


def test_register_hashes_are_salted(auth, app):
    auth.register("alice", PW)
    auth.register("bob", PW)
    first, second = (u["password"] for u in user_rows(app))
    assert first != second


def test_register_does_not_strip_the_password(auth, app):
    spaced = "  spaced pass 123  "
    auth.register("alice", spaced)
    assert check_password_hash(user_rows(app)[0]["password"], spaced)


def test_register_duplicate_username_shows_error_and_adds_no_row(auth, app):
    auth.register("alice", PW)
    response = auth.register("alice", "other-pass-456")
    assert response.status_code == 200
    assert b"already" in response.data.lower()
    rows = user_rows(app)
    assert len(rows) == 1
    assert check_password_hash(rows[0]["password"], PW)  # the original was not overwritten


@pytest.mark.parametrize("data", [
    {}, {"username": "alice"}, {"password": PW},
    {"username": "", "password": PW}, {"username": "   ", "password": PW},
    {"username": "alice", "password": ""},
], ids=["nothing", "no-password", "no-username", "empty-username", "blank-username", "empty-password"])
def test_register_rejects_missing_or_empty_fields(client, app, data):
    response = client.post("/auth/register", data=data)
    assert response.status_code == 200
    assert user_rows(app) == []


@pytest.mark.parametrize("length, accepted", [(7, False), (8, True), (128, True), (129, False)])
def test_register_password_length_bounds(client, app, length, accepted):
    response = client.post("/auth/register", data={"username": "alice", "password": "p" * length})
    assert (response.status_code == 302) is accepted
    assert len(user_rows(app)) == (1 if accepted else 0)


@pytest.mark.parametrize("length, accepted", [(64, True), (65, False)])
def test_register_username_length_bounds(client, app, length, accepted):
    response = client.post("/auth/register", data={"username": "u" * length, "password": PW})
    assert (response.status_code == 302) is accepted
    assert len(user_rows(app)) == (1 if accepted else 0)


def test_register_strips_surrounding_whitespace_from_username(auth, app):
    auth.register("  alice  ", PW)
    assert [u["username"] for u in user_rows(app)] == ["alice"]


# ---------- login ----------

def test_login_page_loads(client):
    assert client.get("/auth/login").status_code == 200


def test_login_success_redirects_and_sets_session(client, auth, app):
    auth.register("alice", PW)
    uid = user_rows(app)[0]["id"]
    with client:
        response = auth.login("alice", PW)
        assert response.status_code == 302
        assert session["user_id"] == uid


@pytest.mark.parametrize("query", [
    "", "?next=https://evil.example/", "?next=//evil.example/", "?next=/\\evil.example",
], ids=["plain", "absolute-url", "scheme-relative", "backslash"])
def test_login_always_redirects_to_a_local_path(client, auth, query):
    auth.register("alice", PW)
    response = client.post("/auth/login" + query, data={"username": "alice", "password": PW})
    location = response.headers["Location"]
    parsed = urlparse(location)
    assert response.status_code == 302
    assert parsed.scheme == "" and parsed.netloc == ""
    assert location.startswith("/") and not location.startswith(("//", "/\\"))


def test_login_wrong_password_and_unknown_user_give_the_same_message(client, auth):
    auth.register("alice", PW)
    for response in (auth.login("alice", "wrong-pass-999"), auth.login("ghost", PW)):
        assert response.status_code == 200
        assert b"Invalid username or password" in response.data


@pytest.mark.parametrize("data", [
    {"username": "alice", "password": "wrong-pass-999"},
    {"username": "ghost", "password": PW},
    {"username": "", "password": ""},
    {"username": "alice"},
    {},
], ids=["wrong-password", "unknown-user", "empty", "no-password", "nothing"])
def test_failed_login_does_not_set_session(client, auth, data):
    auth.register("alice", PW)
    with client:
        response = client.post("/auth/login", data=data)
        assert response.status_code == 200
        assert "user_id" not in session


def test_login_discards_anything_already_in_the_session(client, auth):
    auth.register("alice", PW)
    with client.session_transaction() as s:
        s["planted"] = "attacker-value"
    with client:
        auth.login("alice", PW)
        assert "planted" not in session
        assert "user_id" in session


# ---------- cookies ----------

def test_cookie_config_is_explicit(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_session_cookie_is_sent_with_httponly_and_samesite_lax(auth):
    auth.register("alice", PW)
    cookies = auth.login("alice", PW).headers.getlist("Set-Cookie")
    assert any("session=" in c and "HttpOnly" in c and "SameSite=Lax" in c for c in cookies)


# ---------- logout ----------

def test_logout_clears_the_session(client, auth):
    auth.register("alice", PW)
    with client:
        auth.login("alice", PW)
        assert "user_id" in session
        response = auth.logout()
        assert response.status_code == 302
        assert "user_id" not in session


def test_logout_is_post_only(client):
    assert client.get("/auth/logout").status_code == 405


def test_logout_when_anonymous_is_harmless(auth):
    assert auth.logout().status_code == 302


# ---------- g.user ----------

def test_g_user_is_loaded_for_a_logged_in_user(client, auth):
    auth.register("alice", PW)
    with client:
        auth.login("alice", PW)
        client.get("/auth/login")
        assert g.user["username"] == "alice"


def test_g_user_is_none_for_anonymous(client):
    with client:
        client.get("/auth/login")
        assert g.user is None


def test_stale_session_user_id_is_treated_as_anonymous(client):
    with client.session_transaction() as s:
        s["user_id"] = 9999
    with client:
        response = client.get("/auth/login")
        assert response.status_code == 200
        assert g.user is None
