-- Drop children first: with foreign_keys ON, dropping a parent table
-- that still has referencing rows fails
DROP TABLE IF EXISTS watch;
DROP TABLE IF EXISTS vulnerability;
DROP TABLE IF EXISTS user;

CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE vulnerability (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT UNIQUE NOT NULL,
  -- from KEV, rewritten on every refresh
  vendor TEXT NOT NULL,
  product TEXT NOT NULL,
  name TEXT NOT NULL,
  short_description TEXT NOT NULL,
  date_added TEXT NOT NULL,
  due_date TEXT NOT NULL,
  ransomware_use INTEGER NOT NULL,
  cwes TEXT NOT NULL,
  kev_urls TEXT NOT NULL,
  -- from NVD, filled lazily and kept across KEV refreshes
  nvd_status TEXT,
  nvd_published TEXT,
  nvd_last_modified TEXT,
  cvss_score REAL,
  cvss_version TEXT,
  cvss_severity TEXT,
  cvss_vector TEXT,
  cvss_source TEXT,
  cvss_type TEXT,
  nvd_fetched_at TEXT
);

CREATE TABLE watch (
  user_id INTEGER NOT NULL REFERENCES user (id),
  vuln_id INTEGER NOT NULL REFERENCES vulnerability (id),
  note TEXT NOT NULL DEFAULT '',
  -- TEXT, not TIMESTAMP: no detect_types, so the value stays a plain string
  created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, vuln_id)
);
