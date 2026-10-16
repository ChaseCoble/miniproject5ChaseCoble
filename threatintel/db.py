# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 5

import sqlite3
from datetime import datetime, timedelta

import click
from flask import current_app, g
from flask.cli import with_appcontext

LONG_TTL_STATUSES = ("Analyzed", "Rejected")
LONG_TTL = timedelta(days=30)
SHORT_TTL = timedelta(hours=24)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        # SQLite leaves foreign keys off unless enabled on each connection
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    with current_app.open_resource("schema.sql") as f:
        db.executescript(f.read().decode("utf8"))


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    click.echo("Initialized the database.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)


def upsert_kev(db, rows):
    # ON CONFLICT ... DO UPDATE (not INSERT OR REPLACE) keeps the row id,
    # so watches still point at it, and leaves the NVD columns alone.
    # "with db" commits on success and rolls back on any error, so a
    # failure midway can't leave a partial refresh for a later commit
    with db:
        db.executemany(
            "INSERT INTO vulnerability (cve_id, vendor, product, name, short_description, "
            "date_added, due_date, ransomware_use, cwes, kev_urls) "
            "VALUES (:cve_id, :vendor, :product, :name, :short_description, "
            ":date_added, :due_date, :ransomware_use, :cwes, :kev_urls) "
            "ON CONFLICT (cve_id) DO UPDATE SET "
            "vendor = excluded.vendor, product = excluded.product, name = excluded.name, "
            "short_description = excluded.short_description, date_added = excluded.date_added, "
            "due_date = excluded.due_date, ransomware_use = excluded.ransomware_use, "
            "cwes = excluded.cwes, kev_urls = excluded.kev_urls",
            [{**row, "kev_urls": "\n".join(row["urls"])} for row in rows],
        )


def save_nvd(db, result, now):
    with db:
        db.execute(
            "UPDATE vulnerability SET nvd_status = :nvd_status, nvd_published = :nvd_published, "
            "nvd_last_modified = :nvd_last_modified, cvss_score = :cvss_score, "
            "cvss_version = :cvss_version, cvss_severity = :cvss_severity, "
            "cvss_vector = :cvss_vector, cvss_source = :cvss_source, cvss_type = :cvss_type, "
            "nvd_fetched_at = :nvd_fetched_at WHERE cve_id = :cve_id",
            {**result, "nvd_fetched_at": now.isoformat()},
        )


def nvd_is_stale(row, now):
    fetched_at = row["nvd_fetched_at"]
    if not fetched_at:
        return True
    try:
        fetched_at = datetime.fromisoformat(fetched_at)
    except ValueError:
        return True
    # A naive timestamp can't be compared with an aware "now"; refetch
    if fetched_at.tzinfo is None:
        return True
    # vulnStatus is a free string in NVD's schema, so anything unrecognised
    # gets the short TTL
    ttl = LONG_TTL if row["nvd_status"] in LONG_TTL_STATUSES else SHORT_TTL
    return now - fetched_at > ttl
