import csv
import random
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_CSV = BASE_DIR / "synthetic_evaluation_report.csv"
ROW_COUNT = 5000

FIELDNAMES = [
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


FINDING_POOL = [
    ("Missing HSTS header.", 16),
    ("Missing Content-Security-Policy header.", 14),
    ("Missing X-Content-Type-Options header.", 8),
    ("Missing Referrer-Policy header.", 7),
    ("Neither X-Frame-Options nor CSP frame-ancestors is present.", 12),
    ("Server header exposed: nginx", 9),
    ("Server header exposed: apache", 9),
    ("Server header exposed: iis", 10),
    ("Cookie flags need review.", 11),
    ("Wildcard CORS policy observed.", 13),
    ("Technology banner exposed.", 10),
    ("Redirect observed.", 4),
]


def choose_findings(rng):
    count = rng.randint(0, 6)
    if count == 0:
        return ["No obvious missing baseline headers were detected."]
    chosen = rng.sample(FINDING_POOL, k=count)
    return [item[0] for item in chosen]


def infer_scores(findings, tls_days_remaining, status):
    risk = 0
    for finding, weight in FINDING_POOL:
        if finding in findings:
            risk += weight

    if status >= 400:
        risk += 12
    if status >= 500:
        risk += 18
    if tls_days_remaining <= 0:
        risk += 16
    elif tls_days_remaining < 15:
        risk += 12
    elif tls_days_remaining < 45:
        risk += 7

    threat_score = max(0, min(100, risk + 8))
    protection_score = max(0, 100 - threat_score)

    if threat_score >= 75:
        severity = "Critical"
    elif threat_score >= 55:
        severity = "High"
    elif threat_score >= 30:
        severity = "Medium"
    else:
        severity = "Low"
    return severity, threat_score, protection_score


def build_row(index, rng):
    hostname = f"approved-sim-{index:04d}.example"
    status = rng.choices([200, 204, 301, 302, 403, 404, 500], weights=[45, 4, 10, 9, 10, 8, 4])[0]
    tls_days_remaining = rng.randint(0, 365) if status < 500 else rng.randint(0, 120)
    findings = choose_findings(rng)
    severity, threat_score, protection_score = infer_scores(findings, tls_days_remaining, status)
    return {
        "input_url": f"https://{hostname}",
        "final_url": f"https://{hostname}",
        "severity": severity,
        "threat_score": threat_score,
        "protection_score": protection_score,
        "status": status,
        "tls_days_remaining": tls_days_remaining,
        "findings": " | ".join(findings),
        "report_path": f"/synthetic/reports/{hostname}.md",
        "error": "",
    }


def main():
    rng = random.Random(29)
    rows = [build_row(index, rng) for index in range(1, ROW_COUNT + 1)]
    with OUTPUT_CSV.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} synthetic authorized-style rows to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
