import csv
import ssl
import urllib.parse
from pathlib import Path

import server


BASE_DIR = Path(__file__).resolve().parent
INPUT_CSV = BASE_DIR / "authorized_sites.csv"
OUTPUT_CSV = BASE_DIR / "evaluation_report.csv"


def read_targets(path):
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = []
        for row in reader:
            url = (row.get("url") or "").strip()
            if url:
                rows.append(url)
        return rows


def summarize_headers(headers):
    lowered = {key.lower(): value for key, value in headers.items()}
    return {
        "hsts": lowered.get("strict-transport-security", ""),
        "csp": lowered.get("content-security-policy", ""),
        "x_content_type_options": lowered.get("x-content-type-options", ""),
        "referrer_policy": lowered.get("referrer-policy", ""),
        "x_frame_options": lowered.get("x-frame-options", ""),
        "server_header": lowered.get("server", ""),
    }


def audit_target(url):
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""

    dns_result = server.tool_dns_lookup({"hostname": hostname})
    header_result = server.tool_http_headers({"url": url})
    security_result = server.tool_security_headers_audit({"url": url})

    tls_result = {}
    if parsed.scheme == "https":
        tls_result = server.tool_tls_inspect({"hostname": hostname, "port": parsed.port or 443})

    header_summary = summarize_headers(header_result["headers"])

    return {
        "input_url": url,
        "final_url": header_result["final_url"],
        "status": header_result["status"],
        "dns_addresses": ";".join(dns_result["addresses"]),
        "subject_common_name": tls_result.get("subject_common_name", ""),
        "issuer_common_name": tls_result.get("issuer_common_name", ""),
        "not_after": tls_result.get("not_after", ""),
        "hsts": header_summary["hsts"],
        "csp": header_summary["csp"],
        "x_content_type_options": header_summary["x_content_type_options"],
        "referrer_policy": header_summary["referrer_policy"],
        "x_frame_options": header_summary["x_frame_options"],
        "server_header": header_summary["server_header"],
        "findings": " | ".join(security_result["findings"]),
        "error": "",
    }


def write_report(rows, path):
    fieldnames = [
        "input_url",
        "final_url",
        "status",
        "dns_addresses",
        "subject_common_name",
        "issuer_common_name",
        "not_after",
        "hsts",
        "csp",
        "x_content_type_options",
        "referrer_policy",
        "x_frame_options",
        "server_header",
        "findings",
        "error",
    ]

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    if not INPUT_CSV.exists():
        raise SystemExit(f"Missing input file: {INPUT_CSV}")

    server.SSL_CONTEXT = server.build_ssl_context()
    server.init_db()
    server.seed_knowledge()

    report_rows = []
    for url in read_targets(INPUT_CSV):
        try:
            report_rows.append(audit_target(url))
        except Exception as exc:
            report_rows.append(
                {
                    "input_url": url,
                    "final_url": "",
                    "status": "",
                    "dns_addresses": "",
                    "subject_common_name": "",
                    "issuer_common_name": "",
                    "not_after": "",
                    "hsts": "",
                    "csp": "",
                    "x_content_type_options": "",
                    "referrer_policy": "",
                    "x_frame_options": "",
                    "server_header": "",
                    "findings": "",
                    "error": str(exc),
                }
            )

    write_report(report_rows, OUTPUT_CSV)
    print(f"Wrote {len(report_rows)} rows to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
