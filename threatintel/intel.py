# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 5

import sqlite3
from datetime import timedelta

from flask import (
    Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for,
)

from threatintel.auth import login_required
from threatintel.db import get_db, nvd_is_stale, save_nvd, upsert_kev
from threatintel.fetch import FetchError
from threatintel.sources import parse_kev, parse_nvd, validate_cve_id

bp = Blueprint("intel", __name__)

PER_PAGE = 100
NOTE_MAX = 500
REFRESH_WINDOW = timedelta(hours=1)

# :q = '' matches everything. instr() is a plain substring test, so % and _
# in the search box are literal characters, not LIKE wildcards. lower() is
# ASCII-only in SQLite, which covers CVE IDs and the vendor/product names.
SEARCH_WHERE = (
    "WHERE :q = '' OR instr(lower(cve_id), lower(:q)) > 0 "
    "OR instr(lower(vendor), lower(:q)) > 0 OR instr(lower(product), lower(:q)) > 0"
)


@bp.route("/")
def index():
    q = request.args.get("q", "").strip()
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM vulnerability " + SEARCH_WHERE, {"q": q}).fetchone()[0]
    pages = max(1, -(-total // PER_PAGE))
    # Anything that isn't an integer is page 1; out-of-range is clamped
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        page = 1
    page = min(max(page, 1), pages)
    rows = db.execute(
        "SELECT * FROM vulnerability " + SEARCH_WHERE +
        # cve_id breaks date_added ties so pages are stable
        " ORDER BY date_added DESC, cve_id ASC LIMIT :limit OFFSET :offset",
        {"q": q, "limit": PER_PAGE, "offset": (page - 1) * PER_PAGE},
    ).fetchall()
    return render_template("intel/index.html", rows=rows, q=q, page=page, pages=pages, total=total)


@bp.route("/about")
def about():
    return render_template("intel/about.html")


@bp.route("/cve/<cve_id>")
def detail(cve_id):
    row = get_vuln_or_404(cve_id)
    db = get_db()
    unavailable = False
    now = current_app.config["CLOCK"]()
    if nvd_is_stale(row, now):
        try:
            result = parse_nvd(current_app.config["NVD_FETCHER"](cve_id))
        except (FetchError, ValueError):
            result = None
        if result is None:
            # Nothing is saved, so the next view tries again
            unavailable = True
        else:
            save_nvd(db, result, now)
            row = get_vuln_or_404(cve_id)
    kev_urls = [url for url in row["kev_urls"].splitlines() if url]
    return render_template("intel/detail.html", row=row, kev_urls=kev_urls, unavailable=unavailable)


@bp.route("/watchlist")
@login_required
def watchlist():
    rows = get_db().execute(
        "SELECT v.cve_id, v.vendor, v.product, v.name, w.note, w.created "
        "FROM watch w JOIN vulnerability v ON v.id = w.vuln_id "
        "WHERE w.user_id = ? ORDER BY v.cve_id",
        (g.user["id"],),
    ).fetchall()
    return render_template("intel/watchlist.html", rows=rows)


@bp.route("/watch/<cve_id>/add", methods=("POST",))
@login_required
def watch_add(cve_id):
    vuln = get_vuln_or_404(cve_id)
    db = get_db()
    try:
        with db:
            # The user always comes from the session, never from the form
            db.execute("INSERT INTO watch (user_id, vuln_id) VALUES (?, ?)", (g.user["id"], vuln["id"]))
    except sqlite3.IntegrityError:
        flash(f"{vuln['cve_id']} is already on your watchlist.")
    return redirect(url_for("intel.watchlist"))


@bp.route("/watch/<cve_id>/edit", methods=("GET", "POST"))
@login_required
def watch_edit(cve_id):
    watch = get_own_watch_or_404(cve_id)
    error = None
    note = watch["note"]
    if request.method == "POST":
        note = request.form.get("note", "")
        if len(note) > NOTE_MAX:
            error = f"Note must be at most {NOTE_MAX} characters."
        else:
            db = get_db()
            with db:
                db.execute(
                    "UPDATE watch SET note = ? WHERE user_id = ? AND vuln_id = ?",
                    (note, g.user["id"], watch["vuln_id"]),
                )
            return redirect(url_for("intel.watchlist"))
    return render_template("intel/edit.html", cve_id=watch["cve_id"], note=note, error=error)


@bp.route("/watch/<cve_id>/delete", methods=("POST",))
@login_required
def watch_delete(cve_id):
    watch = get_own_watch_or_404(cve_id)
    db = get_db()
    with db:
        db.execute(
            "DELETE FROM watch WHERE user_id = ? AND vuln_id = ?",
            (g.user["id"], watch["vuln_id"]),
        )
    return redirect(url_for("intel.watchlist"))


@bp.route("/refresh", methods=("POST",))
@login_required
def refresh():
    now = current_app.config["CLOCK"]()
    last = current_app.extensions["threatintel_last_refresh"]
    # One window for the whole app, so the server can't be used to hammer CISA
    if last is not None and now - last < REFRESH_WINDOW:
        flash("The KEV feed was refreshed less than an hour ago. Try again later.")
        return redirect(url_for("intel.index"))
    try:
        rows = parse_kev(current_app.config["KEV_FETCHER"]())
    except (FetchError, ValueError):
        # A failure changes nothing and doesn't start the window
        flash("The KEV feed is unavailable right now. Nothing was changed.")
        return redirect(url_for("intel.index"))
    upsert_kev(get_db(), rows)
    current_app.extensions["threatintel_last_refresh"] = now
    flash(f"Loaded {len(rows)} KEV entries.")
    return redirect(url_for("intel.index"))


def get_vuln_or_404(cve_id):
    # Validate first, so a malformed ID never reaches the database or a fetcher
    if not validate_cve_id(cve_id):
        abort(404)
    row = get_db().execute("SELECT * FROM vulnerability WHERE cve_id = ?", (cve_id,)).fetchone()
    if row is None:
        abort(404)
    return row


def get_own_watch_or_404(cve_id):
    # Scoped to the current user: someone else's watch looks exactly like a missing one
    if not validate_cve_id(cve_id):
        abort(404)
    watch = get_db().execute(
        "SELECT w.vuln_id, w.note, v.cve_id FROM watch w "
        "JOIN vulnerability v ON v.id = w.vuln_id "
        "WHERE v.cve_id = ? AND w.user_id = ?",
        (cve_id, g.user["id"]),
    ).fetchone()
    if watch is None:
        abort(404)
    return watch
