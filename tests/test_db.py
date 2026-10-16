# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 5

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from threatintel.db import get_db, nvd_is_stale, save_nvd, upsert_kev
from threatintel.sources import parse_kev

NOW = datetime(2099, 6, 1, 12, 0, tzinfo=timezone.utc)
NO_CVSS = dict.fromkeys([
    "cvss_score", "cvss_version", "cvss_severity",
    "cvss_vector", "cvss_source", "cvss_type",
])


# ---------- helpers ----------

def insert_vuln(db, cve_id="CVE-2099-0001"):
    db.execute(
        "INSERT INTO vulnerability (cve_id, vendor, product, name, short_description, "
        "date_added, due_date, ransomware_use, cwes, kev_urls) "
        "VALUES (?, 'Acme', 'Widget', 'Acme Widget Test Vulnerability', 'Fake entry.', "
        "'2099-01-01', '2099-01-22', 0, '', '')",
        (cve_id,),
    )
    return db.execute("SELECT id FROM vulnerability WHERE cve_id = ?", (cve_id,)).fetchone()["id"]


def add_user(db, name="alice"):
    return db.execute(
        "INSERT INTO user (username, password) VALUES (?, 'hash-placeholder')", (name,)
    ).lastrowid


def add_watch(db, user_id, vuln_id):
    db.execute("INSERT INTO watch (user_id, vuln_id) VALUES (?, ?)", (user_id, vuln_id))


def count(db, table):
    # table names are constants in this file, never user input
    return db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def rows_for(kev_entry, n=1, **overrides):
    entries = [kev_entry(cveID=f"CVE-2099-{i:04d}", **overrides) for i in range(1, n + 1)]
    return parse_kev({"vulnerabilities": entries})


def nvd_result(**overrides):
    base = {
        "cve_id": "CVE-2099-0001", "nvd_status": "Analyzed",
        "nvd_published": "2099-01-01T00:00:00.000",
        "nvd_last_modified": "2099-01-02T00:00:00.000",
        "cvss_score": 9.3, "cvss_version": "4.0", "cvss_severity": "CRITICAL",
        "cvss_vector": "CVSS:4.0/AV:N", "cvss_source": "nvd@nist.gov", "cvss_type": "Primary",
    }
    base.update(overrides)
    return base


# ---------- connection and schema ----------

def test_get_db_returns_same_connection_within_context(app):
    with app.app_context():
        assert get_db() is get_db()


def test_get_db_connection_is_closed_after_context(app):
    with app.app_context():
        conn = get_db()
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        conn.execute("SELECT 1")


def test_init_db_command_creates_the_three_tables(blank_app):
    result = blank_app.test_cli_runner().invoke(args=["init-db"])
    assert result.exit_code == 0, result.output
    conn = sqlite3.connect(blank_app.config["DATABASE"])
    try:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    finally:
        conn.close()
    assert {"user", "vulnerability", "watch"} <= names


def test_init_db_command_can_run_twice(blank_app):
    runner = blank_app.test_cli_runner()
    assert runner.invoke(args=["init-db"]).exit_code == 0
    assert runner.invoke(args=["init-db"]).exit_code == 0


def test_foreign_keys_pragma_is_on(db):
    assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_watch_has_two_foreign_keys(db):
    fks = db.execute("PRAGMA foreign_key_list(watch)").fetchall()
    assert sorted(fk["table"] for fk in fks) == ["user", "vulnerability"]


def test_watch_rejects_nonexistent_vulnerability(db):
    uid = add_user(db)
    with pytest.raises(sqlite3.IntegrityError):
        add_watch(db, uid, 9999)


def test_watch_rejects_nonexistent_user(db):
    vid = insert_vuln(db)
    with pytest.raises(sqlite3.IntegrityError):
        add_watch(db, 9999, vid)


def test_vulnerability_cve_id_is_unique(db):
    insert_vuln(db, "CVE-2099-0001")
    with pytest.raises(sqlite3.IntegrityError):
        insert_vuln(db, "CVE-2099-0001")


def test_watch_user_and_vulnerability_pair_is_unique(db):
    uid, vid = add_user(db), insert_vuln(db)
    add_watch(db, uid, vid)
    with pytest.raises(sqlite3.IntegrityError):
        add_watch(db, uid, vid)


def test_different_users_can_watch_the_same_vulnerability(db):
    # positive control: UNIQUE must be on the pair, not on vuln_id alone
    vid = insert_vuln(db)
    add_watch(db, add_user(db, "alice"), vid)
    add_watch(db, add_user(db, "bob"), vid)
    assert count(db, "watch") == 2


def test_username_is_unique(db):
    add_user(db, "alice")
    with pytest.raises(sqlite3.IntegrityError):
        add_user(db, "alice")


# ---------- KEV refresh (upsert) ----------

def test_upsert_kev_inserts_rows_with_expected_values(db, kev_entry):
    rows = rows_for(kev_entry, cwes=["CWE-77", "CWE-78"],
                    knownRansomwareCampaignUse="Known",
                    notes="https://a.example/1 ; https://a.example/2")
    upsert_kev(db, rows)
    row = db.execute("SELECT * FROM vulnerability WHERE cve_id = 'CVE-2099-0001'").fetchone()
    assert row["vendor"] == "Acme"
    assert row["due_date"] == "2099-01-22"
    assert row["cwes"] == "CWE-77,CWE-78"
    assert row["ransomware_use"] == 1
    assert row["kev_urls"] == "https://a.example/1\nhttps://a.example/2"
    assert row["cvss_score"] is None
    assert row["nvd_fetched_at"] is None


def test_upsert_kev_is_idempotent(db, kev_entry):
    rows = rows_for(kev_entry, n=3)
    upsert_kev(db, rows)
    upsert_kev(db, rows)
    assert count(db, "vulnerability") == 3


def test_upsert_kev_updates_changed_fields(db, kev_entry):
    upsert_kev(db, rows_for(kev_entry))
    upsert_kev(db, rows_for(kev_entry, dueDate="2099-02-01"))
    got = db.execute("SELECT due_date FROM vulnerability").fetchall()
    assert [r["due_date"] for r in got] == ["2099-02-01"]


def test_upsert_kev_keeps_row_id_and_existing_watches(db, kev_entry):
    upsert_kev(db, rows_for(kev_entry))
    vid = db.execute("SELECT id FROM vulnerability").fetchone()["id"]
    add_watch(db, add_user(db), vid)
    upsert_kev(db, rows_for(kev_entry, dueDate="2099-02-01"))
    assert db.execute("SELECT id FROM vulnerability").fetchone()["id"] == vid
    assert count(db, "watch") == 1


def test_upsert_kev_preserves_nvd_enrichment(db, kev_entry):
    upsert_kev(db, rows_for(kev_entry))
    save_nvd(db, nvd_result(), NOW)
    upsert_kev(db, rows_for(kev_entry, dueDate="2099-02-01"))
    row = db.execute("SELECT * FROM vulnerability").fetchone()
    assert row["cvss_score"] == 9.3
    assert row["nvd_status"] == "Analyzed"
    assert row["nvd_fetched_at"] == NOW.isoformat()
    assert row["due_date"] == "2099-02-01"  # the refresh itself still happened


# ---------- NVD cache ----------

def test_save_nvd_stores_fields_and_fetched_at(db, kev_entry):
    upsert_kev(db, rows_for(kev_entry))
    save_nvd(db, nvd_result(), NOW)
    row = db.execute("SELECT * FROM vulnerability").fetchone()
    assert (row["cvss_score"], row["cvss_version"], row["cvss_severity"]) == (9.3, "4.0", "CRITICAL")
    assert row["cvss_vector"] == "CVSS:4.0/AV:N"
    assert (row["cvss_source"], row["cvss_type"]) == ("nvd@nist.gov", "Primary")
    assert row["nvd_status"] == "Analyzed"
    assert row["nvd_published"] == "2099-01-01T00:00:00.000"
    assert row["nvd_last_modified"] == "2099-01-02T00:00:00.000"
    assert row["nvd_fetched_at"] == NOW.isoformat()


def test_save_nvd_overwrites_previous_enrichment(db, kev_entry):
    upsert_kev(db, rows_for(kev_entry))
    save_nvd(db, nvd_result(cvss_score=9.3), NOW)
    later = NOW + timedelta(days=1)
    save_nvd(db, nvd_result(cvss_score=7.5, nvd_status="Modified"), later)
    row = db.execute("SELECT * FROM vulnerability").fetchone()
    assert row["cvss_score"] == 7.5
    assert row["nvd_status"] == "Modified"
    assert row["nvd_fetched_at"] == later.isoformat()


def test_save_nvd_with_no_cvss_stores_nulls_and_still_marks_fetched(db, kev_entry):
    upsert_kev(db, rows_for(kev_entry))
    save_nvd(db, nvd_result(**NO_CVSS, nvd_status="Undergoing Analysis"), NOW)
    row = db.execute("SELECT * FROM vulnerability").fetchone()
    assert row["cvss_score"] is None and row["cvss_version"] is None
    assert row["nvd_status"] == "Undergoing Analysis"
    assert row["nvd_fetched_at"] == NOW.isoformat()


def test_save_nvd_touches_only_the_named_cve(db, kev_entry):
    upsert_kev(db, rows_for(kev_entry, n=2))
    save_nvd(db, nvd_result(cve_id="CVE-2099-0001"), NOW)
    other = db.execute("SELECT * FROM vulnerability WHERE cve_id = 'CVE-2099-0002'").fetchone()
    assert other["cvss_score"] is None
    assert other["nvd_fetched_at"] is None


@pytest.mark.parametrize("status, age, stale", [
    ("Analyzed", timedelta(days=29), False),
    ("Analyzed", timedelta(days=31), True),
    ("Rejected", timedelta(days=29), False),
    ("Rejected", timedelta(days=31), True),
    ("Undergoing Analysis", timedelta(hours=23), False),
    ("Undergoing Analysis", timedelta(hours=25), True),
    ("Brand New Status", timedelta(hours=23), False),
    ("Brand New Status", timedelta(hours=25), True),
    (None, timedelta(hours=23), False),
    (None, timedelta(hours=25), True),
])
def test_nvd_is_stale_follows_ttl_by_status(status, age, stale):
    row = {"nvd_status": status, "nvd_fetched_at": (NOW - age).isoformat()}
    assert nvd_is_stale(row, NOW) is stale


@pytest.mark.parametrize("status", ["Analyzed", "Undergoing Analysis", None])
def test_nvd_is_stale_when_never_fetched(status):
    assert nvd_is_stale({"nvd_status": status, "nvd_fetched_at": None}, NOW) is True


@pytest.mark.parametrize("bad", ["garbage", "", "2099-13-45"])
def test_nvd_is_stale_when_timestamp_unparseable(bad):
    assert nvd_is_stale({"nvd_status": "Analyzed", "nvd_fetched_at": bad}, NOW) is True

def test_watch_has_a_note_that_defaults_to_empty_and_a_created_timestamp(db):
    uid, vid = add_user(db), insert_vuln(db)
    add_watch(db, uid, vid)
    row = db.execute("SELECT * FROM watch WHERE user_id = ? AND vuln_id = ?", (uid, vid)).fetchone()
    assert row["note"] == ""
    assert isinstance(row["created"], str) and row["created"]
    db.execute("UPDATE watch SET note = ? WHERE user_id = ? AND vuln_id = ?", ("triage first", uid, vid))
    assert db.execute("SELECT note FROM watch").fetchone()["note"] == "triage first"


def test_nvd_is_stale_when_timestamp_has_no_timezone():
    naive = (NOW - timedelta(hours=1)).replace(tzinfo=None).isoformat()
    assert nvd_is_stale({"nvd_status": "Analyzed", "nvd_fetched_at": naive}, NOW) is True


def test_save_nvd_for_unknown_cve_creates_no_row(db):
    save_nvd(db, nvd_result(cve_id="CVE-2099-0404"), NOW)
    assert count(db, "vulnerability") == 0

def test_upsert_kev_failure_midway_leaves_no_partial_rows(db, kev_entry):
    good = rows_for(kev_entry)[0]
    unbindable = {**good, "cve_id": "CVE-2099-0002", "vendor": object()}
    with pytest.raises(Exception):  # loose on purpose: the assertion that matters is below
        upsert_kev(db, [good, unbindable])
    db.commit()  # a view that catches the error and carries on will commit later
    assert count(db, "vulnerability") == 0
