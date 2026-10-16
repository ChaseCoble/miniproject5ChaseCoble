# Design Decisions

Running record of decisions made and findings confirmed between me
(Chase Coble) and Claude during development of Mini Project 5.

Status: **Mine** = I decided. **Proposed, accepted** = Claude proposed it in
design review and I accepted it.

## Data sources and flow

| Decision | Why | Status |
|---|---|---|
| Two sources: CISA KEV and the NVD CVE API, joined on CVE ID | Both are keyless, so a grader can run the app with no secrets. KEV says what is exploited, NVD adds CVSS. | Proposed, accepted |
| KEV is bulk-loaded on an explicit refresh; NVD is fetched lazily on first view of a CVE and cached | NVD's unauthenticated rate limit makes enriching ~1,700 entries up front impractical (limit figure from memory, [PENDING: verify against NVD docs]) | Proposed, accepted |
| CWEs come from KEV, not NVD | Already in the KEV record as a list | Corrected by my curl output |
| Not stored: NVD `affected`, SSVC, NVD descriptions and references | `affected` holds globs, not versions. The rest is scope creep for this assignment. | Proposed, accepted |

## Access and security

| Decision | Why | Status |
|---|---|---|
| Dashboard is public; watchlist, note form and refresh require login | The list is public data, and only user state needs protection | Proposed, accepted |
| Any logged-in user can refresh, at most once per hour | Keeps the server from being used to hammer CISA | Proposed, accepted |
| CSRF protection is out of scope: a documented known limitation | Time-boxed. README lists the exposed state-changing routes and notes SameSite=Lax as a partial mitigation only. | Mine |
| Third-party text is never rendered as HTML (no `\|safe`); only http/https URLs become links | NVD and KEV text is untrusted input | Proposed, accepted |

## CVSS and caching

| Decision | Why | Status |
|---|---|---|
| Version precedence v4.0 > v3.1 > v3.0 > v2; within a version Primary beats Secondary; first entry wins a tie | Prefer the newest scheme and NVD's own analysis | Mine (precedence), Proposed, accepted (Primary rule) |
| Scores from different CVSS versions are sorted together, with the version always shown next to the score | Real data shows the same CVE scoring 9.3 (v4.0) and 10.0 (v3.1), so the version must be visible | Mine |
| Cache TTL: 30 days for `Analyzed` and `Rejected`, 24 hours for anything else | Log4Shell's `lastModified` is 2026-08-11, so analyzed records still change. NVD's schema types `vulnStatus` as a free string, so unknown values fall into the short TTL. | Proposed, corrected from my first draft |
| Timestamps are stored as the raw strings NVD sends | NVD uses a naive format and SSVC uses an offset format. No guessing about time zones. | Proposed, accepted |

## Parsing policy

| Decision | Why | Status |
|---|---|---|
| KEV parsing is strict: every field the parser reads must be present and the right type, and `cwes` must be a list of strings | Chose strict over lenient even though no real entry is missing a key (0 of 1,745), so the policy is deliberate and tested | Mine |
| A bad KEV entry is skipped with exactly one logged warning; a feed with no `vulnerabilities` list raises `ValueError` | One bad entry must not kill a refresh, but a wrong feed must not look like an empty one | Mine |
| Feed-supplied values are logged with `%r` | A hostile value cannot forge log lines | Proposed, accepted |
| NVD: unknown CVE returns `None`; unusable response or malformed record raises `ValueError`; a CVE with no usable metrics returns all-`None` CVSS fields | NVD is one record per call, so a response we can't interpret should show "enrichment unavailable" instead of being cached | Proposed, accepted [PENDING: confirm you accept all five NVD decisions] |
| `vulnStatus` absent gives `None`; `vulnStatus` of the wrong type raises | "NVD didn't say" differs from "NVD sent something uninterpretable" | Proposed, accepted |

## Notes URL extraction (beyond the rubric, kept deliberately)

KEV's `notes` is free text, so the rules come from the real feed, not from guesses:

- Separators are `;`, whitespace, and a comma only when another `http(s)://` follows it. Real entries have bare-comma URL lists (CVE-2023-38606) and a URL with commas inside it (CVE-2009-3459).
- A URL with another URL embedded in its path (archive-style) stays one URL.
- Stripped: a leading `(`, trailing `.` `,` `"`, and a trailing `)` only when unbalanced. Kept: trailing `-` `?` `#`, and balanced parens inside a URL.
- A trailing period is stripped: sentence punctuation is more likely than a real trailing dot. **Mine.**
- Only `http://` and `https://` survive; `javascript:`, `data:` and `ftp:` are dropped. A bare scheme with nothing after it is dropped.

Choices Claude Code made that no test pins, and that I accepted:

- Scheme check is case-sensitive, so `HTTPS://` is dropped. Fails closed.
- No host validation: `https://x` is accepted. The scheme allow-list is the security control.
- [PENDING real-data check] Only a leading `(` is stripped, and trailing `'` `!` `]` `>` are kept. Not seen in the data.
- [PENDING real-data check] A `;` always splits, even inside a URL query string.

## Left unpinned on purpose

Log message wording, and the `","` joiner inside warning text, are not part of the contract.
Tests pin that a warning fires and which entry it names. The mutation run's 7 remaining
survivors are all of this kind.

## Process

- **Git is human-only.** Claude does not run git commands, make commits, or propose git config changes. Claude reports when work is ready to commit; I commit. **Mine.**
- **Tests are the contract.** Tests were drafted in design review (me and Claude, a batch at a time); Claude Code implements and may not edit `tests/` or `pytest.ini`. Enforced with `git diff --exit-code tests/ pytest.ini` after each run, which detects tampering after the fact.
- **Fixtures:** real responses are `nvd_log4shell.json`, `nvd_undergoing_analysis.json` and the `kev_sample.json` entries. Synthetic, derived by editing real ones: `nvd_no_metrics`, `nvd_v2_only`, `nvd_v30_only`, `nvd_empty`.
- **v3.0 caveat:** NVD re-scored the old CVEs I checked with v3.1, so the v3.0 branch is exercised only by a synthetic fixture. I did not verify v3.0's internal `cvssData` fields.
- **Mutation testing:** `tools/mutate.py` runs on a copy of the code. Result for `sources.py`: 108 of 115 caught. The mutation run found 4 real gaps, and each got a test; the existing `sources.py` implementation passed those tests unchanged.
- **Corrections along the way:** my first "no-metrics" edge case was wrong, because the supposed day-old CVE already had scores. My first cache rule (cache `Analyzed` forever) contradicted the data.
