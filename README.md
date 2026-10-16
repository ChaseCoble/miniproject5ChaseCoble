### INF601 - Advanced Programming in Python
### Chase Coble
### Mini Project 5
 
 
# Project Title
 
Flask Web App aggregating CISA KEV and NVD.
 
## Description
 
 
## Getting Started
 
### Dependencies
 
* Describe any prerequisites, libraries, OS version, etc., needed before installing program.
* ex. Windows 10
* List pip install instructions.
 
### Installing
 
* How/where to download your program
* Any modifications needed to be made to files/folders
 
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
 
* How to run the program
* Step-by-step bullets
```
code blocks for commands
```
 
## Help
 
Any advise for common problems or issues.
```
command to run if program contains helper info
```
 
## Known limitations
 
* **Login timing can reveal which usernames exist.** Logging in with an unknown
  username skips the password-hash check, so it responds measurably faster than
  a wrong password for a real account. The error message is identical in both
  cases ("Invalid username or password."). This is accepted for this project and
  not mitigated.
* **No CSRF protection.** The session cookie is set with `SameSite=Lax`, which is
  only a partial mitigation. Current state-changing routes:
    * `POST /auth/register`
    * `POST /auth/login`
    * `POST /auth/logout`
 
## Authors
 
Contributors names and contact info
## Version History
 
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
 
This project is licensed under the [NAME HERE] License - see the LICENSE.md file for details
 
## Acknowledgments
 
