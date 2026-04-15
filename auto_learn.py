import html
import json
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from build_learning_digest import build_digest


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
LEARNING_DIR = REPORTS_DIR / "learning"
SOURCES_PATH = DATA_DIR / "learning_sources.json"
MAX_ITEMS_PER_SOURCE = 12
USER_AGENT = "DarkTraceX-AutoLearn/1.0"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def strip_html(text):
    value = html.unescape(text or "")
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def load_sources():
    payload = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
    return [item for item in payload.get("sources", []) if item.get("enabled", True)]


def fetch_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=40) as response:
        return response.read().decode("utf-8", errors="replace")


def child_text(node, names):
    for name in names:
        child = node.find(name)
        if child is not None and child.text:
            return child.text.strip()
    return ""


def parse_feed(xml_text, source_name):
    root = ET.fromstring(xml_text)
    entries = []

    rss_items = root.findall(".//item")
    atom_entries = root.findall(".//{http://www.w3.org/2005/Atom}entry")

    if rss_items:
        for item in rss_items[:MAX_ITEMS_PER_SOURCE]:
            entries.append(
                {
                    "source_name": source_name,
                    "title": child_text(item, ["title"]),
                    "link": child_text(item, ["link"]),
                    "summary": strip_html(child_text(item, ["description", "summary"])),
                    "published": child_text(item, ["pubDate", "published", "updated"]),
                }
            )
    elif atom_entries:
        for entry in atom_entries[:MAX_ITEMS_PER_SOURCE]:
            link = ""
            for link_node in entry.findall("{http://www.w3.org/2005/Atom}link"):
                href = (link_node.attrib.get("href") or "").strip()
                if href:
                    link = href
                    break
            entries.append(
                {
                    "source_name": source_name,
                    "title": child_text(entry, ["{http://www.w3.org/2005/Atom}title"]),
                    "link": link,
                    "summary": strip_html(
                        child_text(
                            entry,
                            [
                                "{http://www.w3.org/2005/Atom}summary",
                                "{http://www.w3.org/2005/Atom}content",
                            ],
                        )
                    ),
                    "published": child_text(
                        entry,
                        [
                            "{http://www.w3.org/2005/Atom}published",
                            "{http://www.w3.org/2005/Atom}updated",
                        ],
                    ),
                }
            )

    return [item for item in entries if item.get("title")]


def classify_item(item):
    text = " ".join([item.get("title", ""), item.get("summary", "")]).lower()

    severity = "low"
    if any(token in text for token in ["critical", "actively exploited", "rce", "remote code execution", "zero-day"]):
        severity = "high"
    elif any(token in text for token in ["vulnerability", "cve-", "exploit", "advisory", "patch", "malware"]):
        severity = "medium"

    categories = {
        "vulnerability": ["cve-", "vulnerability", "advisory", "patch", "security update"],
        "malware": ["malware", "ransomware", "trojan", "worm", "botnet"],
        "phishing": ["phishing", "credential", "social engineering", "invoice scam"],
        "cloud": ["cloud", "aws", "azure", "gcp", "kubernetes", "container"],
        "identity": ["identity", "sso", "oauth", "login", "token", "session"],
    }

    category = "general"
    for name, markers in categories.items():
        if any(marker in text for marker in markers):
            category = name
            break

    item["severity"] = severity
    item["category"] = category
    item["fetched_at"] = utc_now()
    return item


def write_snapshot(snapshot):
    LEARNING_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = LEARNING_DIR / f"learning-snapshot-{timestamp}.json"
    path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    return path


def main():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    LEARNING_DIR.mkdir(parents=True, exist_ok=True)
    sources = load_sources()
    snapshot = {
        "fetched_at": utc_now(),
        "sources": [],
        "items": [],
        "items_collected": 0,
    }

    for source in sources:
        source_record = {
            "name": source.get("name", "Unnamed source"),
            "url": source.get("url", ""),
            "status": "ok",
            "items_collected": 0,
        }
        try:
            xml_text = fetch_text(source_record["url"])
            items = parse_feed(xml_text, source_record["name"])
            classified = [classify_item(item) for item in items]
            snapshot["items"].extend(classified)
            source_record["items_collected"] = len(classified)
        except (urllib.error.URLError, TimeoutError, ET.ParseError, ValueError) as exc:
            source_record["status"] = f"error: {exc}"
        snapshot["sources"].append(source_record)

    snapshot["items_collected"] = len(snapshot["items"])
    snapshot_path = write_snapshot(snapshot)
    digest_md_path, digest_json_path = build_digest(hours=72)
    print(f"Wrote learning snapshot to {snapshot_path}")
    print(f"Wrote digest to {digest_md_path}")
    print(f"Wrote digest JSON to {digest_json_path}")


if __name__ == "__main__":
    main()
