# CLAUDE.md

Standing instructions for Claude Code in this repository. Read the whole file before acting.

## Environment constraints (do not work around these)

- This account (`claude_agent`) is permanently denied execute access to `setfacl`, `chmod` and `chown` at the OS level (ACL-denied on the binaries themselves). This is intentional and permanent, not a bug. Do not attempt these commands, variations of them, or workarounds (including via sudo, which is also unavailable to this account). If a task seems to require a permission or ownership change, stop and tell the user what is needed and why.
- This account has no sudo access, for anything, under any circumstance. Do not propose `sudo` as a fix for a permission error.
- Access is scoped per project by ACL, granted by `claude_init` and revoked by `claude_close`. Assume you can read and write only inside this project directory and its subdirectories, never above or outside it.
- This project uses a venv. Run `source .venv/bin/activate` before `pytest -q`.

## Workflow rules

- **TDD.** For any new function or method, a failing test must exist before the implementation is written, unless the user explicitly directs otherwise for a specific case.
- **Pairing partner, not a code generator.** The user must be able to explain every line submitted. For anything non-trivial, explain the approach before writing code. Exception: a handoff that names test files to make pass (for example "Make tests/test_db.py pass. Rules are in CLAUDE.md.") is an explicit go-ahead to implement. The tests are the specification, so do not stop to ask for confirmation, and report what you did afterward.
- **Confirm understanding when the task is ambiguous.** State your understanding and wait, or ask, rather than assuming.
- **Do not guess at API or library behavior.** If you are not certain what a function, endpoint or library does, say so and suggest checking the documentation or testing it directly.
- **Record decisions.** When the user confirms a decision or finding, offer a one-line entry for `DECISIONS.md` and wait for approval. Never add entries unprompted, and never state reasoning the user has not given.
- **Never change the repository's history or index.** No `git commit`, `git push`, `git add`, `git reset` or similar. The user commits.

## Security posture

- Treat this environment as deliberately least-privilege. If something you would normally expect to be able to do fails with a permission error, that is very likely intentional scoping, not a misconfiguration to fix. Report it, do not circumvent it.
- Do not attempt to install, invoke, or rely on tools that would require privileges this account does not have.
- File ownership during a session is not a long-term audit signal. `claude_close` reassigns ownership back to the human operator when a project concludes. Conversation logs serve as provenance instead.

---

## Project: Threat Intel Aggregator (INF601 Mini Project 5)

### Assignment
A small Flask app that aggregates two public sources, CISA KEV and NVD, joined on CVE ID.
- 5+ commits (the user commits), and a README covering the project, installing requirements, initializing the database, running the dev server, and an AI Usage section.
- Flask app: proper folder structure, 5+ pages on a template structure, one page with a form and proper GET and POST routes, SQLite with 2+ tables linked by a foreign key, Bootstrap in the templates (at minimum a modal), and a register and login system.

### Rules for every slice
- Never edit `tests/` or `pytest.ini`. If a test looks wrong, stop and say so.
- Implement only what the tests require. No helpers nothing calls.
- Run `pytest -q` with the venv active. Stop at green.
- Report every guess the tests do not pin down, and every place you deviated from this file.
- Every `.py` file outside `tests/` starts with exactly this header. Headers inside `tests/` are added by the user.
```
  # INF601 - Advanced Programming in Python
  # Chase Coble
  # Mini Project 5
```
- All SQL values are bound as parameters. Never build SQL with string formatting. Use no SQL feature newer than SQLite 3.24 (for example, no `RETURNING`), because the grader's machine may be older.
- Third-party text (KEV, NVD) is untrusted. Log it with `%r`, and render it escaped.
- No `|safe` in any template.

### Modules
- **`threatintel/sources.py`:** stdlib only, pure functions. No Flask import, no network, no file I/O.
- **`threatintel/fetch.py`:** stdlib only (`urllib`, `json`, `http.client`), no Flask. Network access only through the injected `urlopen` parameter, which defaults to `urllib.request.urlopen`. Never read a response without a bound.
- The "no Flask" rule applies to `sources.py` and `fetch.py` only. `db.py`, `__init__.py`, `auth.py` and `intel.py` use Flask.
- **`create_app(test_config=None)`** follows the Flask tutorial factory. It creates the instance folder, registers the `init-db` CLI command and the DB teardown, and registers two blueprints: `auth` (`threatintel/auth.py`, `url_prefix` `/auth`: register, login, POST-only logout, and `g.user` loading) and `intel` (see Views below).
- **`get_db`** sets `row_factory = sqlite3.Row` and `PRAGMA foreign_keys = ON` per connection.
- **Database writers** wrap their statements in `with db:`, which commits on success and rolls back on an exception, so a failure leaves no partial writes.
- **Auth:** Werkzeug password hashes. Login ignores `?next=` and always redirects to `/`. Cookies are `HttpOnly` and `SameSite=Lax`.
- **`SECRET_KEY`** comes from the `THREATINTEL_SECRET_KEY` environment variable, otherwise a random per-process key, and is never `"dev"`. `instance/config.py` overrides both.

## Views slice (tests/test_views.py, tests/test_config.py)

- Config keys, set by default in `create_app`: `KEV_FETCHER` = `threatintel.fetch.fetch_kev`, `NVD_FETCHER` = `threatintel.fetch.fetch_nvd`, `CLOCK` = a function returning `datetime.now(timezone.utc)` (timezone-aware, never naive).
- Views read those three keys from `current_app.config` **at request time**, never at import time and never by importing the real functions directly.
- The refresh limiter's state lives per app (for example in `app.extensions`), never in a module-level global.
- `login_required` lives in `auth.py`. For an anonymous user it redirects to `auth.login`. It guards `/watchlist`, `/watch/<cve_id>/add`, `/watch/<cve_id>/edit`, `/watch/<cve_id>/delete` and `/refresh`.

### Routes
- Public: `/` (dashboard), `/cve/<cve_id>`, `/about`, plus the auth pages. Login and logout redirect to `/`.
- POST-only (GET is 405): `/watch/<cve_id>/add`, `/watch/<cve_id>/delete`, `/refresh`.
- `/watch/<cve_id>/edit` is GET (form prefilled with the current note) and POST.

### Dashboard
- Rows ordered `date_added DESC, cve_id ASC` (the tie-break keeps pages stable), 100 per page, `?page=`. An invalid or out-of-range page value is clamped, never an error.
- `?q=` searches `cve_id`, `vendor` and `product`, case-insensitively, with bound parameters.

### CVE detail
- Validate with `validate_cve_id` first. A malformed ID gives 404 and **no fetch**. A valid ID not in the database gives 404 and no fetch.
- Fetch NVD only when `nvd_is_stale(row, CLOCK())` is true. On success, `parse_nvd` then `save_nvd(db, result, CLOCK())`.
- `FetchError`, `ValueError` from the parser, or `parse_nvd` returning `None` all mean the same thing: render the KEV data with a notice containing the word "unavailable", and save nothing.
- Show the CVSS score with its version beside it, the severity, the NVD status, a link to `https://nvd.nist.gov/vuln/detail/<validated id>`, and the stored KEV reference URLs.

### Watchlist
- Every watch query is scoped to `g.user["id"]`. A watch that is not yours behaves exactly like a missing one: 404.
- Add: 404 for an unknown or malformed ID. A duplicate adds no row and flashes a message containing "already".
- Edit note: max 500 characters, saved on POST, redirect to a local path.
- Delete: a POST form inside a Bootstrap modal on the watchlist page.

### Refresh
- POST, login required, at most once per hour for the whole app (all users share one window), measured with `CLOCK`.
- A failed fetch, or a feed that is not KEV, changes nothing and does **not** start the window. On success: `parse_kev` then `upsert_kev`.

## Templates and styling

Edit only `threatintel/templates/` and `threatintel/static/` for styling work. Bootstrap 5.3 from the vendored files only: no CDN, no web fonts, no icon fonts, no new JavaScript libraries. Custom CSS goes in `threatintel/static/style.css`, linked after Bootstrap. A system font stack is fine.

### Behavior the tests pin (do not break)
- Every page extends `base.html`. `base.html` has a `<link>` to `bootstrap.min.css` and a `<script src>` for `bootstrap.bundle.min.js`, both under `/static/vendor/bootstrap/` (via `url_for('static', filename='vendor/bootstrap/...')`).
- Every `href` on the CVE detail page, including nav and footer, starts with `/`, `#`, `http://` or `https://`. Use double quotes. Never `href=""`, `javascript:`, `mailto:` or `tel:`. Render a reference link only for URLs starting with `http://` or `https://`.
- The anonymous nav contains exactly `href="/auth/login"` and `href="/auth/register"`, with no query string.
- The logged-in nav has a `<form>` whose opening tag contains both `post` and `/auth/logout`.
- Watchlist delete: one modal per watch row, rendered server-side. The button has `data-bs-toggle="modal"`, the modal element's class attribute starts with `class="modal`, and the `<form>` inside it has `method="post"` and an `action` containing `/watch/<cve_id>/delete`. Do not set the action with JavaScript.
- Dashboard and watchlist show CVE IDs only for the rows they list. No "recent", "top" or "related" panels.
- Detail page: put the CVSS score and its version in one element, for example `9.3 (CVSS v4.0)`. The two must be within 40 characters of each other, markup included. The NVD link is exactly `href="https://nvd.nist.gov/vuln/detail/<id>"`.
- Messages contain the exact words "unavailable" (NVD outage) and "already" (duplicate watch).
- Hostile text must still render escaped.

## Styling run authorization (delete this block after the run)
- The styling run is an explicit "just write it" for `threatintel/templates/` and `threatintel/static/` only. It adds no new function, so the TDD rule does not apply. Do not touch any `.py` file.
- Run `pytest -q` after each change. It must stay green with the same count as before you started. If a test breaks, fix the template, not the test.
