# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 5

import logging
import re

logger = logging.getLogger(__name__)

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.ASCII)

KEV_STRING_KEYS = (
    "vendorProject", "product", "vulnerabilityName",
    "shortDescription", "dateAdded", "dueDate",
    "knownRansomwareCampaignUse", "notes",
)
KEV_REQUIRED_KEYS = ("cveID", "cwes") + KEV_STRING_KEYS

# Split notes into tokens on ";" or whitespace, or on a comma that
# directly starts another URL (commas elsewhere can be part of a URL)
NOTES_SPLIT_RE = re.compile(r"[;\s]+|,(?=https?://)")
# Scheme plus at least one character, so a bare "https://" is rejected
URL_RE = re.compile(r"https?://.")


def validate_cve_id(cve_id):
    # fullmatch (not match + $) so a trailing "\n" is rejected;
    # re.ASCII so \d only matches 0-9, not full-width digits
    return isinstance(cve_id, str) and CVE_ID_RE.fullmatch(cve_id) is not None


def parse_notes_urls(notes):
    # Labels and prose are just tokens that aren't http(s) URLs, so they drop out.
    if not notes:
        return []
    urls = []
    for token in NOTES_SPLIT_RE.split(notes):
        token = token.lstrip("(")
        # Trim trailing punctuation from the surrounding sentence; only drop
        # ")" when it's unbalanced, so "x-(y)" keeps its own paren
        while token.endswith((".", ",", '"')) or (
            token.endswith(")") and token.count(")") > token.count("(")
        ):
            token = token[:-1]
        if URL_RE.match(token):
            urls.append(token)
    return urls


def parse_kev(data):
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("not a KEV feed: missing 'vulnerabilities' list")

    rows = []
    for entry in data["vulnerabilities"]:
        if not isinstance(entry, dict):
            logger.warning("skipping KEV entry: not an object (%s)", type(entry).__name__)
            continue
        # %r escapes control characters so a hostile cveID can't forge log lines
        missing = [key for key in KEV_REQUIRED_KEYS if key not in entry]
        if missing:
            logger.warning("skipping KEV entry %r: missing %s", entry.get("cveID"), ",".join(missing))
            continue
        if not validate_cve_id(entry["cveID"]):
            logger.warning("skipping KEV entry %r: invalid CVE ID", entry["cveID"])
            continue
        bad_types = [key for key in KEV_STRING_KEYS if not isinstance(entry[key], str)]
        cwes = entry["cwes"]
        if not (isinstance(cwes, list) and all(isinstance(cwe, str) for cwe in cwes)):
            bad_types.append("cwes")
        if bad_types:
            logger.warning("skipping KEV entry %r: wrong type for %s", entry["cveID"], ",".join(bad_types))
            continue
        rows.append({
            "cve_id": entry["cveID"],
            "vendor": entry["vendorProject"],
            "product": entry["product"],
            "name": entry["vulnerabilityName"],
            "short_description": entry["shortDescription"],
            "date_added": entry["dateAdded"],
            "due_date": entry["dueDate"],
            "ransomware_use": entry["knownRansomwareCampaignUse"] == "Known",
            "cwes": ",".join(entry["cwes"]),
            "urls": parse_notes_urls(entry["notes"]),
        })
    return rows
