# Threat Intel Aggregator

INF601 - Advanced Programming in Python · Chase Coble · Mini Project 5

A small Flask web app that combines two public vulnerability sources: CISA's
Known Exploited Vulnerabilities (KEV) catalog and the NIST National
Vulnerability Database (NVD), joined on CVE ID.

## Description

KEV says which CVEs are being exploited in the wild. NVD adds CVSS severity and
analysis status. The app joins the two so a CVE's page shows both.

* **KEV** is bulk-loaded into SQLite when a logged-in user clicks
  **Refresh KEV feed** (limited to once per hour for the whole app).
* **NVD** is fetched lazily, the first time a CVE's detail page is opened, then
  cached. The cache lasts 30 days for `Analyzed` and `Rejected` records and
  24 hours for anything else.
* Neither source needs an API key, so no secrets are stored in the repo.
* Registered users keep a personal watchlist with a private note per CVE.

| Page | Route | Login |
|---|---|---|
| Dashboard (search, pagination) | `/` | no |
| CVE detail (KEV facts + NVD enrichment) | `/cve/<cve_id>` | no |
| About / sources | `/about` | no |
| Register | `/auth/register` | no |
| Log in | `/auth/login` | no |
| Watchlist (delete confirmation in a Bootstrap modal) | `/watchlist` | yes |
| Edit note (form, GET and POST) | `/watch/<cve_id>/edit` | yes |

## Getting Started

### Dependencies

* Python 3 (developed and tested on 3.13)
* SQLite 3.24 or later. Check with:

```
  python3 -c "import sqlite3; print(sqlite3.sqlite_version)"
```
* Internet access for the KEV refresh and NVD lookups (the test suite needs none)
* Python packages are listed in `requirements.txt`

### Installing

```
git clone https://github.com/<your-github-username>/miniproject5ChaseCoble.git
cd miniproject5ChaseCoble
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Bootstrap 5.3 is vendored in `threatintel/static/vendor/bootstrap/`, so the app
loads no scripts or styles from a CDN.

### Initializing the database

```
flask --app threatintel init-db
```

**Warning: `init-db` destroys all existing data.** It drops the `user`,
`vulnerability` and `watch` tables and recreates them empty, so every account,
watchlist entry, note and cached feed record is deleted. This is the same
behaviour as the `init-db` command in the official Flask tutorial. Run it once
when setting up, and again only when you want a clean database.

### Executing program

```
flask --app threatintel run
```

Then open <http://127.0.0.1:5000>. Add `--debug` for the reloader and debugger,
and only on a loopback address.

**First run: the dashboard is empty until KEV is loaded.**

1. Run `init-db` (above), then start the server.
2. Click **Register** and create an account, then log in.
3. Click **Refresh KEV feed** on the dashboard. This downloads about 1.8 MB and
   loads roughly 1,700 entries.
4. Open any CVE. The first view fetches its NVD data and caches it.

### Configuration

| Setting | How | Default |
|---|---|---|
| Session secret key | `THREATINTEL_SECRET_KEY` environment variable, or `instance/config.py` | A random key generated at startup |

Set the variable for sessions that survive a restart:

```
export THREATINTEL_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

### Running the tests

```
pytest -q
```

The suite runs fully offline: an autouse fixture blocks real network access, and
the KEV/NVD fetchers and the clock are injected as fakes. Fixtures in
`tests/fixtures/` are saved real responses, plus a few derived ones listed in
`tests/fixtures/README`.

## Project layout

```
threatintel/
  __init__.py      app factory (create_app), config, blueprint registration
  auth.py          register, login, logout, login_required
  intel.py         dashboard, CVE detail, watchlist, refresh
  db.py            connection, init-db, upsert_kev, save_nvd, cache TTL
  schema.sql       user, vulnerability, watch (watch has two foreign keys)
  sources.py       pure parsers: parse_kev, parse_nvd, select_cvss, ...
  fetch.py         the only module that touches the network
  templates/       base.html and the page templates
  static/          vendored Bootstrap and style.css
tests/             pytest suite and fixtures
DECISIONS.md       design decisions and their reasoning
```

Design decisions, and who made each one, are recorded in `DECISIONS.md`.

## Help

* **The dashboard is empty.** Log in and click **Refresh KEV feed**. The
  database starts empty by design.
* **A CVE page says NVD enrichment is unavailable.** NVD may be unreachable, or
  may not have analyzed a very new CVE yet. The KEV data still shows. Nothing is
  cached on failure, so reloading the page retries.
* **Everyone was logged out after a restart.** Without
  `THREATINTEL_SECRET_KEY`, each start generates a new key.
* **`sqlite3.OperationalError` mentioning `ON CONFLICT`.** SQLite is older than
  3.24. See Dependencies.
* **Refresh says to wait.** Refresh is limited to once per hour.

## Known limitations

* **No CSRF protection.** The session cookie is set with `SameSite=Lax`, which
  is only a partial mitigation. State-changing routes:
    * `POST /auth/register`
    * `POST /auth/login`
    * `POST /auth/logout`
    * `POST /watch/<cve_id>/add`
    * `POST /watch/<cve_id>/edit`
    * `POST /watch/<cve_id>/delete`
    * `POST /refresh`
* **Account enumeration.** Registration reports that a username is taken. Login
  returns one identical error message for a wrong password and an unknown user,
  but an unknown user skips the password-hash check, so it responds measurably
  faster. Accepted and not mitigated.
* **No login lockout or rate limiting.**
* **Session cookie has no `Secure` flag**, because the dev server runs over
  plain HTTP. The secret key is random per process unless configured, so a
  restart logs everyone out and several workers would not share sessions.
* **Anyone can trigger NVD lookups.** Viewing an uncached CVE fetches it, even
  when logged out, and nothing throttles that. Only the KEV refresh is limited.
* **The refresh limiter lives in memory.** It resets on restart, and two
  simultaneous requests could both pass the check.
* **KEV entries that leave the feed are never deleted.**
* **The fetch timeout is per socket operation, not a total deadline.**
* **CVSS scores come from different versions** (v4.0, v3.1, v3.0, v2) and are not
  directly comparable. Each is shown with its version, and the app prefers the
  newest version, then NVD's own (Primary) score over a secondary source's.
* **Search is case-insensitive for ASCII only.**
* **This is the Flask development server**, not a production deployment.

## AI Usage

TODO: write this section yourself before submitting.

## Authors

Chase Coble

## Version History

* 0.4 - Web app
    * `auth` blueprint: register, login, POST-only logout
    * `intel` blueprint: dashboard with search and pagination, CVE detail with lazy NVD enrichment, watchlist with a Bootstrap delete modal, note editing, rate-limited KEV refresh
    * Bootstrap 5.3 templates, vendored locally
* 0.3 - Database and fetch layer
    * `threatintel/fetch.py`: `fetch_kev` and `fetch_nvd` with an injectable `urlopen`, explicit timeout, User-Agent, a capped response read, CVE ID validation before the request, and all failures mapped to `FetchError`
    * `threatintel/db.py` and `schema.sql`: `user`, `vulnerability` and `watch` tables (`watch` has foreign keys to both, plus a note and created timestamp), the `init-db` command, `upsert_kev`, `save_nvd` and the status-based NVD cache TTL (`nvd_is_stale`)
    * Database writers are transactional (`with db:`), so a failed refresh leaves no partial rows
    * `create_app` factory following the Flask tutorial
* 0.2 - NVD parsing
    * `parse_nvd`: one CVE record from the NVD API to a flat dict; unknown CVE gives `None`, malformed data raises `ValueError`
    * `select_cvss`: picks one CVSS score by version precedence (v4.0 > v3.1 > v3.0 > v2), then Primary over Secondary, skipping unusable entries
* 0.1 - KEV parsing
    * `parse_kev`: strict parsing of the CISA KEV feed, skipping bad entries with one logged warning each
    * `parse_notes_urls`: extracts only http/https URLs from KEV's free-text notes
    * `validate_cve_id`

## License

Coursework submitted for INF601. No license is granted for reuse. Bootstrap,
vendored under `threatintel/static/vendor/bootstrap/`, is MIT licensed and keeps
its own license notice.

## Acknowledgments

* [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
* [NIST National Vulnerability Database](https://nvd.nist.gov/). This product uses data from the NVD API but is not endorsed or certified by the NVD.
* [Bootstrap](https://getbootstrap.com/)
* The official Flask tutorial, which the app factory, auth blueprint and test fixtures follow
* Claude (Anthropic), used as described in AI Usage
