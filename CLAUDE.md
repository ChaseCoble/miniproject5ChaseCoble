# CLAUDE.md — Template

Copy this into each new project directory and flesh out the
project-specific sections. The Environment Constraints and Workflow
Rules sections below should generally stay as-is across projects unless
the underlying environment actually changes — they reflect the Dev VM's
identity model and standing rules, not anything specific to this project.

---

## Environment Constraints (do not attempt to work around these)

- **This account (claude_agent) is permanently denied execute access to
  `setfacl`, `chmod`, and `chown`** at the OS level (ACL-denied on the
  binaries themselves). This is intentional and permanent, not a bug.
  Do not attempt these commands, variations of them, or workarounds
  (including via sudo, which is also unavailable to this account). If a
  task seems to require a permission or ownership change, stop and tell
  the user what's needed and why — do not try to route around it.
- **This account has no sudo access at all**, for anything, under any
  circumstance. Do not propose `sudo` prefixes as a fix for a permission
  error.
- **Access is scoped per-project via ACL**, granted by `claude_init` and
  revoked by `claude_close`. Assume you can only read/write within the
  current project directory and its own subdirectories — nothing above
  or outside it, even if a task seems to call for it.

- This project is venv. Run source .venv/bin/activate before running pytest -q

## Workflow Rules

- **TDD discipline**: for any new function/method, a failing test should
  exist before implementation is written. Do not write implementation
  ahead of its test unless the user explicitly directs otherwise for a
  specific case.
- **You are a pairing partner, not a code generator.** The user must be
  able to explain every line submitted. When asked to implement
  something, prefer explaining your approach and reasoning before
  writing code, especially for anything non-trivial — the user may want
  to write it themselves after understanding it, rather than having you
  write it outright.
- **Read and confirm understanding before implementing**, when the task
  is ambiguous or you haven't been given an explicit "just write it"
  instruction. Don't assume — ask, or state your understanding and wait
  for confirmation, if there's real ambiguity in what's being asked.
- **Do not fabricate or guess at API/library behavior** you're not
  certain of. If uncertain what a real endpoint, library function, or
  system actually does, say so and suggest checking documentation or
  testing directly, rather than presenting a guess as fact.

- **On confirmation of finding or decision, record** prompt user, and keep a running document of decisions made and findings between user and claude to show agentic workflow
## Security Posture

- Treat this environment as deliberately least-privilege. If something
  you'd normally expect to be able to do fails due to a permission
  error, that is very likely intentional scoping, not a
  misconfiguration to fix. Report it, don't circumvent it.
- Do not attempt to install, invoke, or rely on tools that would require
  privileges this account doesn't have.
- Ownership of files created during a session is not preserved as a
  long-term audit signal — `claude_close` reassigns ownership back to
  the human operator on project conclusion. Do not treat file ownership
  as meaningful provenance; conversation logs serve that purpose instead.

---

## Project-Specific Section (fill in per project)

### What this project is
- Create a simple Flask app of my choice
- Requires 5 commits
- README.md explaining the project, how to install requiremnts, how to initialize the database, and how to run the dev server. Include an AI usage section
- Flask app must have the following:
	- Proper folder structure
	- 5 pages using a proper template structure
	- At least one page with a form and proper GET and POST routes
	- SQLITE database with at least two tables linked by a foreign key
	- Use Bootstrap in your templates, at minimum make us of a modal
	- Must include a register and login system


### Specifics
- We are going to do a simple threat intel feed aggregator
- Never edit tests/ or pytest.ini. If a test looks wrong, stop and say so.
- sources.py is stdlib-only, pure functions, no Flask import, no network, no file I/O.
- Header comment on every .py file (the rubric item).
- - # INF601 - Advanced Programming in Python
- - # Chase Coble
- - # Mini Project 5
- Implement only what tests require. No uncalled helpers.
- Run pytest -q, stop at green.
- Report any guess the tests don’t pin down. 
- threatintel/fetch.py: stdlib only (urllib, json, http.client), no Flask. Network access only through the injected urlopen parameter, which defaults to urllib.request.urlopen. Never read a response without a bound.
- The “no Flask” rule applies to sources.py and fetch.py only. db.py and __init__.py use Flask.
- create_app(test_config=None) follows the Flask tutorial factory: it creates the instance folder, registers the init-db CLI command and the DB teardown, and has no blueprints yet.
get_db sets row_factory = sqlite3.Row and PRAGMA foreign_keys = ON per connection.
- Database writers wrap their statements in with db: so a failure rolls back and leaves no partial writes. All SQL values are bound as parameters; never build SQL with string formatting.
### Open questions / things intentionally deferred
