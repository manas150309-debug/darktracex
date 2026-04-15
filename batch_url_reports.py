import csv
from pathlib import Path

import server


BASE_DIR = Path(__file__).resolve().parent
INPUT_CSV = BASE_DIR / "authorized_sites.csv"
OUTPUT_CSV = BASE_DIR / "evaluation_report.csv"
REPORTS_DIR = BASE_DIR / "reports"
SUMMARY_MD = REPORTS_DIR / "batch_summary.md"


def read_targets(path):
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        targets = []
        for row in reader:
            raw = (row.get("url") or "").strip()
            if raw:
                targets.append(raw)
        return targets


def write_csv(rows):
    fieldnames = [
        "input_url",
        "final_url",
        "severity",
        "threat_score",
        "protection_score",
        "status",
        "tls_days_remaining",
        "findings",
        "report_path",
        "error",
    ]
    with OUTPUT_CSV.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_summary(rows):
    REPORTS_DIR.mkdir(exist_ok=True)
    ok_rows = [row for row in rows if not row["error"]]
    failed_rows = [row for row in rows if row["error"]]

    lines = [
        "# Batch URL Threat Summary",
        "",
        f"- Total targets: {len(rows)}",
        f"- Successful analyses: {len(ok_rows)}",
        f"- Failed analyses: {len(failed_rows)}",
        "",
        "## Executive Summary",
        "",
    ]

    if ok_rows:
        severity_counts = {}
        for row in ok_rows:
            severity_counts[row["severity"]] = severity_counts.get(row["severity"], 0) + 1
        for severity in ["Critical", "High", "Medium", "Low"]:
            if severity in severity_counts:
                lines.append(f"- {severity}: {severity_counts[severity]}")
        average_threat = round(sum(int(row["threat_score"]) for row in ok_rows) / len(ok_rows))
        lines.append(f"- Average threat score: {average_threat}/100")
    else:
        lines.append("- No successful analyses were completed.")

    lines.extend(["", "## Site Results", ""])
    for row in ok_rows:
        lines.extend(
            [
                f"### {row['final_url']}",
                "",
                f"- Severity: {row['severity']}",
                f"- Threat score: {row['threat_score']}/100",
                f"- Protection score: {row['protection_score']}/100",
                f"- HTTP status: {row['status']}",
                f"- TLS days remaining: {row['tls_days_remaining'] or 'n/a'}",
                f"- Report: {row['report_path']}",
                f"- Main findings: {row['findings']}",
                "",
            ]
        )

    if failed_rows:
        lines.extend(["## Failures", ""])
        for row in failed_rows:
            lines.append(f"- {row['input_url']}: {row['error']}")

    SUMMARY_MD.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")


def main():
    if not INPUT_CSV.exists():
        raise SystemExit(f"Missing input file: {INPUT_CSV}")

    server.SSL_CONTEXT = server.build_ssl_context()
    server.init_db()
    server.seed_knowledge()

    rows = []
    for target in read_targets(INPUT_CSV):
        try:
            normalized_url = server.extract_target_url(target) or server.validate_url(target)
            result = server.tool_create_url_report_file({"url": normalized_url})
            detailed = server.tool_url_threat_report({"url": normalized_url})
            rows.append(
                {
                    "input_url": target,
                    "final_url": result["url"],
                    "severity": result["severity"],
                    "threat_score": result["threat_score"],
                    "protection_score": 100 - result["threat_score"],
                    "status": detailed["status"],
                    "tls_days_remaining": detailed["tls_days_remaining"] if detailed["tls_days_remaining"] is not None else "",
                    "findings": " | ".join(detailed["findings"]),
                    "report_path": result["report_path"],
                    "error": "",
                }
            )
        except Exception as exc:
            rows.append(
                {
                    "input_url": target,
                    "final_url": "",
                    "severity": "",
                    "threat_score": "",
                    "protection_score": "",
                    "status": "",
                    "tls_days_remaining": "",
                    "findings": "",
                    "report_path": "",
                    "error": str(exc),
                }
            )

    write_csv(rows)
    write_summary(rows)
    print(f"Wrote {len(rows)} rows to {OUTPUT_CSV}")
    print(f"Wrote markdown summary to {SUMMARY_MD}")


if __name__ == "__main__":
    main()
