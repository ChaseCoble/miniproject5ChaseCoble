# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 5

import re
from datetime import timedelta
from urllib.parse import urlparse

import pytest

from threatintel.db import get_db
from threatintel.fetch import FetchError

ID1, ID2, ID3 = "CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"
PAYLOAD = "<script>alert(1)</script>"
ESCAPED = b"&lt;script&gt;alert(1)&lt;/script&gt;"
SECRET_NOTE = "alice-private-triage-note"


# ---------- helpers ----------

def query(app, sql, params=()):
    with app.app_context():
        return [dict(r) for r in get_db().execute(sql, params).fetchall()]


def watch(app, username, cve_id, note=""):
    with app.app_context():
        db = get_db()
        uid = db.execute("SELECT id FROM user WHERE username = ?", (username,)).fetchone()["id"]
        vid = db.execute("SELECT id FROM vulnerability WHERE cve_id = ?", (cve_id,)).fetchone()["id"]
        db.execute("INSERT INTO watch (user_id, vuln_id, note) VALUES (?, ?, ?)", (uid, vid, note))
        db.commit()


def watch_rows(app):
    return query(
        app,
        "SELECT u.username AS username, v.cve_id AS cve_id, w.note AS note "
        "FROM watch w JOIN user u ON u.id = w.user_id JOIN vulnerability v ON v.id = w.vuln_id "
        "ORDER BY u.username, v.cve_id",
    )


def vuln_row(app, cve_id=ID1):
    return query(app, "SELECT * FROM vulnerability WHERE cve_id = ?", (cve_id,))[0]


def cve_ids_in(data):
    return set(re.findall(rb"CVE-2099-\d{4}", data))


def form_tags(data):
    return re.findall(rb"<form[^>]*>", data)


@pytest.fixture
def three(seed, kev_entry):
    seed([kev_entry(cveID=i, vendorProject="Acme", product="Widget") for i in (ID1, ID2, ID3)])


# ---------- public pages and dashboard ----------

@pytest.mark.parametrize("path", ["/", "/about", "/auth/login", "/auth/register"])
def test_public_pages_load_for_anonymous_users(client, path):
    assert client.get(path).status_code == 200


def test_dashboard_loads_with_an_empty_database(client):
    assert client.get("/").status_code == 200


def test_dashboard_lists_the_vulnerabilities(client, three):
    assert cve_ids_in(client.get("/").data) == {i.encode() for i in (ID1, ID2, ID3)}


def test_dashboard_search_matches_vendor_product_and_cve_id_case_insensitively(client, seed, kev_entry):
    seed([
        kev_entry(cveID=ID1, vendorProject="Acme", product="Widget"),
        kev_entry(cveID=ID2, vendorProject="Globex", product="Gadget"),
    ])

    def found(q):
        return cve_ids_in(client.get("/", query_string={"q": q}).data)

    assert found("acme") == {ID1.encode()}
    assert found("GADGET") == {ID2.encode()}
    assert found("cve-2099-0002") == {ID2.encode()}
    assert found("zzz-no-match") == set()


@pytest.mark.parametrize("q", ["' OR 1=1 --", "'; DROP TABLE vulnerability; --", '" OR ""="', "%", "_"])
def test_dashboard_search_survives_sql_metacharacters(client, three, app, q):
    assert client.get("/", query_string={"q": q}).status_code == 200
    assert len(query(app, "SELECT * FROM vulnerability")) == 3


def test_dashboard_search_injection_string_matches_nothing(client, three):
    data = client.get("/", query_string={"q": "' OR 1=1 --"}).data
    assert cve_ids_in(data) == set()


def test_dashboard_shows_at_most_100_rows_per_page(client, seed, kev_entry):
    seed([kev_entry(cveID=f"CVE-2099-{i:04d}") for i in range(1, 151)])
    assert len(cve_ids_in(client.get("/").data)) == 100


def test_dashboard_pages_are_disjoint_and_cover_everything(client, seed, kev_entry):
    # every row has the same date_added, so only a deterministic tie-break keeps pages stable
    seed([kev_entry(cveID=f"CVE-2099-{i:04d}", dateAdded="2099-01-01") for i in range(1, 151)])
    page1 = cve_ids_in(client.get("/", query_string={"page": 1}).data)
    page2 = cve_ids_in(client.get("/", query_string={"page": 2}).data)
    assert not (page1 & page2)
    assert len(page1 | page2) == 150
    assert cve_ids_in(client.get("/").data) == page1


@pytest.mark.parametrize("page", ["abc", "0", "-1", "99999", "1.5", ""])
def test_dashboard_invalid_page_values_do_not_crash(client, three, page):
    assert client.get("/", query_string={"page": page}).status_code == 200


@pytest.mark.parametrize("path", ["/", f"/cve/{ID1}"])
def test_kev_text_is_html_escaped(client, seed, kev_entry, fetchers, path):
    seed([kev_entry(cveID=ID1, vulnerabilityName=PAYLOAD, shortDescription=PAYLOAD, product=PAYLOAD)])
    data = client.get(path).data
    assert PAYLOAD.encode() not in data
    assert ESCAPED in data


# ---------- detail page and NVD enrichment ----------

def test_detail_first_view_fetches_nvd_once_shows_score_with_version_and_caches(client, three, fetchers, clock, app):
    response = client.get(f"/cve/{ID1}")
    assert response.status_code == 200
    assert fetchers.nvd_calls == [ID1]
    assert re.search(rb"9\.3.{0,40}4\.0|4\.0.{0,40}9\.3", response.data, re.S)
    row = vuln_row(app)
    assert row["cvss_score"] == 9.3
    assert row["nvd_fetched_at"] == clock.now.isoformat()


def test_detail_second_view_does_not_fetch_again(client, three, fetchers):
    client.get(f"/cve/{ID1}")
    client.get(f"/cve/{ID1}")
    assert fetchers.nvd_calls == [ID1]


@pytest.mark.parametrize("status, wait, refetch", [
    ("Undergoing Analysis", timedelta(hours=23), False),
    ("Undergoing Analysis", timedelta(hours=25), True),
    ("Analyzed", timedelta(days=29), False),
    ("Analyzed", timedelta(days=31), True),
])
def test_detail_refetches_only_when_the_cache_is_stale(client, three, fetchers, clock, status, wait, refetch):
    base = fetchers.nvd_doc_for

    def with_status(cve_id):
        doc = base(cve_id)
        doc["vulnerabilities"][0]["cve"]["vulnStatus"] = status
        return doc

    fetchers.nvd_doc_for = with_status
    client.get(f"/cve/{ID1}")
    clock.advance(wait)
    client.get(f"/cve/{ID1}")
    assert len(fetchers.nvd_calls) == (2 if refetch else 1)


@pytest.mark.parametrize("bad", [
    "CVE-2021-1", "cve-2099-0001", "CVE-2099-0001%0A", "CVE-2099-0001&x=1", "CVE-2099-0001;x",
])
def test_detail_malformed_id_is_404_and_never_reaches_the_fetcher(client, three, fetchers, bad):
    assert client.get(f"/cve/{bad}").status_code == 404
    assert fetchers.nvd_calls == []


def test_detail_valid_but_unknown_cve_is_404_and_never_reaches_the_fetcher(client, three, fetchers):
    assert client.get("/cve/CVE-2099-9999").status_code == 404
    assert fetchers.nvd_calls == []


def test_detail_nvd_failure_still_shows_kev_data_and_caches_nothing(client, seed, kev_entry, fetchers, app):
    seed([kev_entry(cveID=ID1, vendorProject="Acme")])
    fetchers.nvd_error = FetchError("simulated outage")
    response = client.get(f"/cve/{ID1}")
    assert response.status_code == 200
    assert b"Acme" in response.data
    assert b"unavailable" in response.data.lower()
    row = vuln_row(app)
    assert row["nvd_fetched_at"] is None and row["cvss_score"] is None


@pytest.mark.parametrize("make_doc", [
    lambda cve_id: {"vulnerabilities": "nope"},
    lambda cve_id: {},
    lambda cve_id: {"vulnerabilities": []},
], ids=["malformed", "not-nvd", "unknown-to-nvd"])
def test_detail_unusable_nvd_response_is_treated_as_unavailable(client, three, fetchers, app, make_doc):
    fetchers.nvd_doc_for = make_doc
    response = client.get(f"/cve/{ID1}")
    assert response.status_code == 200
    assert b"unavailable" in response.data.lower()
    assert vuln_row(app)["nvd_fetched_at"] is None


def test_detail_recovers_after_a_failed_fetch(client, three, fetchers, app):
    fetchers.nvd_error = FetchError("down")
    client.get(f"/cve/{ID1}")
    fetchers.nvd_error = None
    client.get(f"/cve/{ID1}")
    assert fetchers.nvd_calls == [ID1, ID1]
    assert vuln_row(app)["nvd_fetched_at"] is not None


def test_detail_escapes_text_that_came_from_nvd(client, three, fetchers):
    base = fetchers.nvd_doc_for

    def hostile(cve_id):
        doc = base(cve_id)
        metrics = doc["vulnerabilities"][0]["cve"]["metrics"]
        metrics["cvssMetricV40"][0]["cvssData"]["vectorString"] = "<img src=x onerror=alert(1)>"
        return doc

    fetchers.nvd_doc_for = hostile
    data = client.get(f"/cve/{ID1}").data
    assert b"<img src=x" not in data
    assert b"&lt;img src=x onerror=alert(1)&gt;" in data


@pytest.mark.parametrize("bad_url", ["javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,x", "vbscript:x"])
def test_detail_never_renders_a_non_http_url_as_a_link(client, three, fetchers, app, bad_url):
    # planted straight into the DB, bypassing the parser: the template must defend itself too
    with app.app_context():
        db = get_db()
        db.execute("UPDATE vulnerability SET kev_urls = ? WHERE cve_id = ?",
                   (bad_url + "\nhttps://ok.example/a", ID1))
        db.commit()
    hrefs = re.findall(rb'href="([^"]*)"', client.get(f"/cve/{ID1}").data)
    assert b"https://ok.example/a" in hrefs
    assert all(h.startswith((b"/", b"#", b"http://", b"https://")) for h in hrefs)


def test_detail_links_to_nvd_using_the_validated_id(client, three, fetchers):
    data = client.get(f"/cve/{ID1}").data
    assert b'href="https://nvd.nist.gov/vuln/detail/' + ID1.encode() + b'"' in data


def test_detail_shows_kev_reference_urls_as_links(client, seed, kev_entry, fetchers):
    seed([kev_entry(cveID=ID1, notes="https://a.example/1 ; https://a.example/2")])
    hrefs = re.findall(rb'href="([^"]*)"', client.get(f"/cve/{ID1}").data)
    assert b"https://a.example/1" in hrefs and b"https://a.example/2" in hrefs


# ---------- login gate ----------

@pytest.mark.parametrize("path", ["/watchlist", f"/watch/{ID1}/edit"])
def test_gated_pages_redirect_anonymous_users_to_login(client, three, path):
    response = client.get(path)
    assert response.status_code == 302
    assert urlparse(response.headers["Location"]).path == "/auth/login"


@pytest.mark.parametrize("path", [f"/watch/{ID1}/add", f"/watch/{ID1}/edit", f"/watch/{ID1}/delete", "/refresh"])
def test_gated_posts_redirect_anonymous_users_and_change_nothing(client, three, fetchers, app, path):
    response = client.post(path, data={"note": "x"})
    assert response.status_code == 302
    assert urlparse(response.headers["Location"]).path == "/auth/login"
    assert watch_rows(app) == []
    assert fetchers.kev_calls == 0


@pytest.mark.parametrize("path", [f"/watch/{ID1}/add", f"/watch/{ID1}/delete", "/refresh"])
def test_mutating_routes_reject_get(alice, three, path):
    assert alice.get(path).status_code == 405


# ---------- watchlist ----------

def test_watch_add_creates_a_row_for_the_logged_in_user_only(alice, bob, three, app):
    response = alice.post(f"/watch/{ID1}/add")
    assert response.status_code == 302
    assert watch_rows(app) == [{"username": "alice", "cve_id": ID1, "note": ""}]


def test_watch_add_ignores_a_user_id_in_the_form(alice, bob, three, app):
    alice.post(f"/watch/{ID1}/add", data={"user_id": "2", "username": "bob"})
    assert [r["username"] for r in watch_rows(app)] == ["alice"]


def test_watch_add_duplicate_makes_no_second_row_and_says_so(alice, three, app):
    alice.post(f"/watch/{ID1}/add")
    response = alice.post(f"/watch/{ID1}/add", follow_redirects=True)
    assert response.status_code == 200
    assert b"already" in response.data.lower()
    assert len(watch_rows(app)) == 1


@pytest.mark.parametrize("cve", ["CVE-2099-9999", "CVE-2021-1", "cve-2099-0001"])
def test_watch_add_unknown_or_malformed_id_is_404(alice, three, app, cve):
    assert alice.post(f"/watch/{cve}/add").status_code == 404
    assert watch_rows(app) == []


def test_watchlist_shows_only_the_current_users_watches(alice, bob, three, app):
    watch(app, "alice", ID1)
    watch(app, "bob", ID2)
    ids = cve_ids_in(alice.get("/watchlist").data)
    assert ids == {ID1.encode()}


def test_watchlist_loads_for_a_user_with_no_watches(alice):
    assert alice.get("/watchlist").status_code == 200


def test_watchlist_escapes_notes(alice, three, app):
    watch(app, "alice", ID1, note="<i>note-payload</i>")
    data = alice.get("/watchlist").data
    assert b"<i>note-payload</i>" not in data
    assert b"&lt;i&gt;note-payload&lt;/i&gt;" in data


def test_watchlist_delete_button_opens_a_modal_holding_a_post_form(alice, three, app):
    watch(app, "alice", ID1)
    data = alice.get("/watchlist").data
    assert b'data-bs-toggle="modal"' in data
    assert b'class="modal' in data
    target = f"/watch/{ID1}/delete".encode()
    assert any(target in f and b"post" in f.lower() for f in form_tags(data))


def test_base_template_loads_bootstrap_css_and_js(client):
    data = client.get("/").data
    assert re.search(rb"<link[^>]+bootstrap[^>]*\.css", data, re.I)
    assert re.search(rb"<script[^>]+bootstrap[^>]*\.js", data, re.I)


def test_nav_offers_logout_as_a_post_form_when_logged_in(alice):
    assert any(b"/auth/logout" in f and b"post" in f.lower() for f in form_tags(alice.get("/").data))


def test_nav_offers_login_and_register_when_anonymous(client):
    data = client.get("/").data
    assert b'href="/auth/login"' in data and b'href="/auth/register"' in data


# ---------- edit note ----------

def test_edit_note_get_shows_the_current_note(alice, three, app):
    watch(app, "alice", ID1, note="triage first")
    response = alice.get(f"/watch/{ID1}/edit")
    assert response.status_code == 200
    assert b"triage first" in response.data


def test_edit_note_get_escapes_the_stored_note(alice, three, app):
    watch(app, "alice", ID1, note="<i>note-payload</i>")
    data = alice.get(f"/watch/{ID1}/edit").data
    assert b"<i>note-payload</i>" not in data
    assert b"&lt;i&gt;note-payload&lt;/i&gt;" in data


def test_edit_note_post_updates_the_note_and_redirects_locally(alice, three, app):
    watch(app, "alice", ID1)
    response = alice.post(f"/watch/{ID1}/edit", data={"note": "triage first"})
    assert response.status_code == 302
    location = urlparse(response.headers["Location"])
    assert location.scheme == "" and location.netloc == ""
    assert watch_rows(app) == [{"username": "alice", "cve_id": ID1, "note": "triage first"}]


@pytest.mark.parametrize("length, accepted", [(500, True), (501, False)])
def test_edit_note_length_limit(alice, three, app, length, accepted):
    watch(app, "alice", ID1, note="old")
    response = alice.post(f"/watch/{ID1}/edit", data={"note": "n" * length})
    assert (response.status_code == 302) is accepted
    assert watch_rows(app)[0]["note"] == ("n" * length if accepted else "old")


def test_edit_note_can_be_cleared(alice, three, app):
    watch(app, "alice", ID1, note="old")
    alice.post(f"/watch/{ID1}/edit", data={"note": ""})
    assert watch_rows(app)[0]["note"] == ""


@pytest.mark.parametrize("method", ["get", "post"])
def test_edit_note_for_a_cve_you_do_not_watch_is_404(alice, three, method):
    assert getattr(alice, method)(f"/watch/{ID1}/edit").status_code == 404


# ---------- other users' watches ----------

@pytest.fixture
def alice_watch(alice, bob, three, app):
    watch(app, "alice", ID1, note=SECRET_NOTE)


def test_other_users_cannot_read_a_watch_note(bob, alice_watch):
    response = bob.get(f"/watch/{ID1}/edit")
    assert response.status_code == 404
    assert SECRET_NOTE.encode() not in response.data


def test_other_users_cannot_change_a_watch_note(bob, alice_watch, app):
    assert bob.post(f"/watch/{ID1}/edit", data={"note": "hijacked"}).status_code == 404
    assert watch_rows(app)[0]["note"] == SECRET_NOTE


def test_other_users_cannot_delete_a_watch(bob, alice_watch, app):
    assert bob.post(f"/watch/{ID1}/delete").status_code == 404
    assert len(watch_rows(app)) == 1


def test_watching_the_same_cve_gives_each_user_an_independent_note(alice, bob, three, app):
    watch(app, "alice", ID1, note="alice's note")
    watch(app, "bob", ID1, note="bob's note")
    bob.post(f"/watch/{ID1}/edit", data={"note": "bob edited"})
    assert watch_rows(app) == [
        {"username": "alice", "cve_id": ID1, "note": "alice's note"},
        {"username": "bob", "cve_id": ID1, "note": "bob edited"},
    ]


def test_delete_removes_only_my_watch_and_keeps_the_vulnerability(alice, bob, three, app):
    watch(app, "alice", ID1)
    watch(app, "bob", ID1)
    watch(app, "alice", ID2)
    response = alice.post(f"/watch/{ID1}/delete")
    assert response.status_code == 302
    assert [(r["username"], r["cve_id"]) for r in watch_rows(app)] == [("alice", ID2), ("bob", ID1)]
    assert len(query(app, "SELECT * FROM vulnerability")) == 3


def test_delete_of_a_watch_you_do_not_have_is_404(alice, three):
    assert alice.post(f"/watch/{ID1}/delete").status_code == 404


# ---------- refresh ----------

def test_refresh_loads_the_feed_into_the_database(alice, fetchers, app):
    response = alice.post("/refresh")
    assert response.status_code == 302
    assert fetchers.kev_calls == 1
    ids = [r["cve_id"] for r in query(app, "SELECT cve_id FROM vulnerability ORDER BY cve_id")]
    assert ids == [ID1, ID2, ID3]


def test_refresh_is_limited_to_once_an_hour_across_all_users(alice, bob, fetchers, clock):
    alice.post("/refresh")
    clock.advance(timedelta(minutes=59))
    bob.post("/refresh")
    assert fetchers.kev_calls == 1
    clock.advance(timedelta(minutes=2))
    alice.post("/refresh")
    assert fetchers.kev_calls == 2


def test_refresh_fetch_failure_changes_nothing_and_does_not_start_the_window(alice, fetchers, app):
    fetchers.kev_error = FetchError("down")
    assert alice.post("/refresh").status_code == 302
    assert query(app, "SELECT * FROM vulnerability") == []
    fetchers.kev_error = None
    alice.post("/refresh")
    assert fetchers.kev_calls == 2
    assert len(query(app, "SELECT * FROM vulnerability")) == 3


@pytest.mark.parametrize("feed", [{}, {"count": 1}, {"vulnerabilities": "nope"}],
                         ids=["empty", "no-list", "wrong-type"])
def test_refresh_with_a_feed_that_is_not_kev_changes_nothing(alice, fetchers, app, feed):
    fetchers.kev_feed = feed
    assert alice.post("/refresh").status_code == 302
    assert query(app, "SELECT * FROM vulnerability") == []


def test_refresh_skips_bad_entries_but_loads_the_rest(alice, fetchers, kev_entry, app):
    fetchers.kev_feed = {"vulnerabilities": [kev_entry(cveID="not-a-cve"), kev_entry(cveID=ID1)]}
    alice.post("/refresh")
    assert [r["cve_id"] for r in query(app, "SELECT cve_id FROM vulnerability")] == [ID1]


def test_refresh_keeps_enrichment_and_watches(alice, fetchers, clock, app):
    alice.post("/refresh")
    alice.get(f"/cve/{ID1}")
    alice.post(f"/watch/{ID1}/add")
    clock.advance(timedelta(hours=2))
    alice.post("/refresh")
    assert fetchers.kev_calls == 2
    assert vuln_row(app)["cvss_score"] == 9.3
    assert len(watch_rows(app)) == 1
