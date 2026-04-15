import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
LEARNING_DIR = REPORTS_DIR / "learning"
DIGEST_MD_PATH = REPORTS_DIR / "three-day-learning-digest.md"
DIGEST_JSON_PATH = REPORTS_DIR / "three-day-learning-digest.json"


def utc_now():
    return datetime.now(timezone.utc)


def parse_timestamp(value):
    if not value:
        return None
    candidate = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_recent_snapshot_items(hours=72):
    cutoff = utc_now() - timedelta(hours=hours)
    items = []
    snapshots = []

    if not LEARNING_DIR.exists():
        return snapshots, items

    for path in sorted(LEARNING_DIR.glob("learning-snapshot-*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        fetched_at = parse_timestamp(payload.get("fetched_at"))
        if fetched_at and fetched_at < cutoff:
            continue

        snapshots.append(
            {
                "file": path.name,
                "fetched_at": payload.get("fetched_at"),
                "items_collected": payload.get("items_collected", 0),
            }
        )
        for item in payload.get("items", []):
            item = dict(item)
            item["_snapshot"] = path.name
            items.append(item)

    return snapshots, items


def dedupe_items(items):
    unique = {}
    for item in items:
        key = (item.get("link") or item.get("title") or "").strip().lower()
        if not key:
            continue
        existing = unique.get(key)
        candidate_time = parse_timestamp(item.get("published")) or parse_timestamp(item.get("fetched_at")) or utc_now()
        if not existing:
            unique[key] = item
            unique[key]["_sort_time"] = candidate_time.isoformat()
            continue

        existing_time = parse_timestamp(existing.get("published")) or parse_timestamp(existing.get("fetched_at")) or utc_now()
        if candidate_time > existing_time:
            unique[key] = item
            unique[key]["_sort_time"] = candidate_time.isoformat()
    return list(unique.values())


def build_digest(hours=72):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    LEARNING_DIR.mkdir(parents=True, exist_ok=True)

    snapshots, raw_items = load_recent_snapshot_items(hours=hours)
    items = dedupe_items(raw_items)
    items.sort(
        key=lambda item: parse_timestamp(item.get("published")) or parse_timestamp(item.get("fetched_at")) or utc_now(),
        reverse=True,
    )

    severity_counts = Counter(item.get("severity", "medium") for item in items)
    category_counts = Counter(item.get("category", "general") for item in items)
    source_counts = Counter(item.get("source_name", "unknown") for item in items)

    top_items = items[:12]
    top_sources = [{"source": name, "count": count} for name, count in source_counts.most_common(6)]
    top_categories = [{"category": name, "count": count} for name, count in category_counts.most_common(8)]

    summary_lines = [
        "# DarkTraceX Three-Day Learning Digest",
        "",
        f"Generated at: {utc_now().isoformat()}",
        f"Window: last {hours} hours",
        "",
        "Easy summary:",
    ]

    if not items:
        summary_lines.extend(
            [
                "No learning snapshots were found in the requested window.",
                "",
                "What to do next:",
                "- Run `python3 auto_learn.py` once.",
                "- Or wait for the login/background autolearn job to collect security feed data.",
            ]
        )
    else:
        summary_lines.extend(
            [
                f"- Snapshots checked: {len(snapshots)}",
                f"- Unique items collected: {len(items)}",
                f"- High-priority items: {severity_counts.get('high', 0)}",
                f"- Medium-priority items: {severity_counts.get('medium', 0)}",
                f"- Low-priority items: {severity_counts.get('low', 0)}",
                "",
                "Top topics:",
            ]
        )
        for item in top_categories:
            summary_lines.append(f"- {item['category']}: {item['count']}")

        summary_lines.extend(["", "Most active sources:"])
        for item in top_sources:
            summary_lines.append(f"- {item['source']}: {item['count']}")

        summary_lines.extend(["", "What stands out in simple language:"])
        if severity_counts.get("high", 0):
            summary_lines.append("- Some higher-risk security items appeared. Review the high-priority entries first.")
        else:
            summary_lines.append("- No high-priority surge was observed in the latest learning window.")
        if category_counts:
            dominant_category = top_categories[0]["category"]
            summary_lines.append(f"- The most common topic recently was `{dominant_category}`.")
        if top_sources:
            summary_lines.append(f"- The noisiest source in this window was `{top_sources[0]['source']}`.")

        summary_lines.extend(["", "Top items:"])
        for item in top_items:
            summary_lines.append(f"- [{item.get('severity', 'medium').upper()}] {item.get('title', 'Untitled item')}")
            summary_lines.append(f"  Source: {item.get('source_name', 'unknown')}")
            if item.get("published"):
                summary_lines.append(f"  Published: {item['published']}")
            if item.get("summary"):
                summary_lines.append(f"  Summary: {item['summary']}")
            if item.get("link"):
                summary_lines.append(f"  Link: {item['link']}")
            summary_lines.append("")

    digest_payload = {
        "generated_at": utc_now().isoformat(),
        "hours": hours,
        "snapshot_count": len(snapshots),
        "unique_item_count": len(items),
        "severity_counts": dict(severity_counts),
        "top_categories": top_categories,
        "top_sources": top_sources,
        "items": top_items,
        "snapshots": snapshots[-12:],
    }

    DIGEST_MD_PATH.write_text("\n".join(summary_lines).strip() + "\n", encoding="utf-8")
    DIGEST_JSON_PATH.write_text(json.dumps(digest_payload, indent=2), encoding="utf-8")
    return DIGEST_MD_PATH, DIGEST_JSON_PATH


if __name__ == "__main__":
    md_path, json_path = build_digest(hours=72)
    print(f"Wrote learning digest to {md_path}")
    print(f"Wrote learning digest JSON to {json_path}")
