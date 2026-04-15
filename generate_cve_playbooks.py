import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_CVE_PLAYBOOKS = DATA_DIR / "cve_playbooks_kb.json"
OUTPUT_WEBSITE_GUIDES = DATA_DIR / "website_analysis_kb.json"


PRODUCTS = [
    ("apache", "http-server"),
    ("apache", "tomcat"),
    ("apache", "struts"),
    ("apache", "kafka"),
    ("nginx", "web-server"),
    ("openssl", "tls-library"),
    ("openssh", "sshd"),
    ("php", "cgi-runtime"),
    ("python", "web-framework"),
    ("django", "application-server"),
    ("flask", "application-server"),
    ("nodejs", "runtime"),
    ("express", "application-server"),
    ("spring", "framework"),
    ("java", "application-runtime"),
    ("jetty", "application-server"),
    ("iis", "web-server"),
    ("microsoft", "exchange"),
    ("microsoft", "sharepoint"),
    ("microsoft", "sql-server"),
    ("windows", "server"),
    ("linux", "kernel"),
    ("ubuntu", "server"),
    ("debian", "server"),
    ("redhat", "enterprise-linux"),
    ("vmware", "esxi"),
    ("citrix", "adc"),
    ("fortinet", "fortios"),
    ("paloalto", "pan-os"),
    ("f5", "big-ip"),
    ("atlassian", "confluence"),
    ("atlassian", "jira"),
    ("oracle", "weblogic"),
    ("mysql", "database-server"),
    ("postgresql", "database-server"),
    ("mongodb", "database-server"),
    ("redis", "cache-server"),
    ("elasticsearch", "cluster"),
    ("kibana", "dashboard"),
    ("grafana", "dashboard"),
    ("gitlab", "devops-platform"),
    ("jenkins", "automation-server"),
    ("kubernetes", "control-plane"),
    ("docker", "engine"),
    ("rundeck", "automation-server"),
    ("zimbra", "mail-server"),
    ("drupal", "cms"),
    ("wordpress", "cms"),
    ("joomla", "cms"),
    ("adobe", "coldfusion"),
]

VULN_TYPES = [
    ("remote-code-execution", "Remote code execution through crafted input or unsafe processing."),
    ("sql-injection", "Database query manipulation through unsanitized application input."),
    ("auth-bypass", "Authentication or authorization checks can be bypassed."),
    ("ssrf", "Server-side request forgery can reach unintended internal or cloud resources."),
    ("path-traversal", "File path handling can expose or modify unintended resources."),
    ("deserialization", "Unsafe object or session deserialization can allow code execution."),
    ("command-injection", "User-controlled data can reach system shell or process execution."),
    ("memory-corruption", "Memory handling flaws may lead to crashes or code execution."),
    ("info-disclosure", "Sensitive configuration, tokens, memory, or files may be exposed."),
    ("privilege-escalation", "An attacker may gain elevated privileges after initial access."),
    ("token-leakage", "Session, API, or authentication tokens can be exposed."),
    ("config-bypass", "Protective configuration assumptions can be bypassed or neutralized."),
    ("web-shell-risk", "Post-exploitation file write or management exposure may allow web shell placement."),
    ("api-abuse", "API workflow misuse can enable unauthorized actions or bulk abuse."),
    ("supply-chain", "Build, package, or update paths can introduce malicious or unsafe code."),
    ("tls-weakness", "TLS deployment or certificate handling can reduce trust or confidentiality."),
    ("header-hardening", "Baseline web security headers are missing or ineffective."),
    ("session-risk", "Session lifecycle or cookie handling can expose authenticated users."),
    ("redirect-abuse", "Redirect or gateway behavior can enable phishing or token leakage."),
    ("logging-exposure", "Logs, traces, or observability paths may leak sensitive operational data."),
]

WEBSITE_FINDINGS = [
    ("missing-hsts", "Missing HSTS reduces browser-side HTTPS enforcement."),
    ("missing-csp", "Missing Content-Security-Policy weakens browser-side script restrictions."),
    ("missing-xcto", "Missing X-Content-Type-Options can increase MIME confusion risk."),
    ("missing-referrer-policy", "Missing Referrer-Policy may leak navigation context."),
    ("server-header-exposure", "Server header exposure reveals implementation details."),
    ("weak-tls-window", "Short certificate lifetime visibility helps track rotation hygiene."),
    ("redirect-chain", "Redirect chains affect trust, caching, and edge policy validation."),
    ("cookie-scope", "Cookie scope and flags affect session exposure risk."),
    ("frame-controls", "Clickjacking protections depend on frame restrictions."),
    ("cache-controls", "Cache behavior influences token and page exposure risk."),
]


def build_cve_playbooks():
    documents = []
    counter = 1
    for vendor, product in PRODUCTS:
        for vuln_type, summary in VULN_TYPES:
            title = f"CVE Triage Playbook: {vendor.title()} {product.replace('-', ' ').title()} {vuln_type.replace('-', ' ').title()}"
            content = "\n".join(
                [
                    f"Vendor/Product: {vendor.title()} {product.replace('-', ' ').title()}",
                    f"Playbook Type: {vuln_type.replace('-', ' ').title()}",
                    f"Summary: {summary}",
                    f"Likely exposure area: internet-facing services, admin interfaces, API endpoints, or plugin surfaces related to {product.replace('-', ' ')}.",
                    "Initial checks: confirm product version, identify exposed services, review authentication paths, and inspect reverse proxy or edge controls.",
                    "Detection ideas: review access logs, admin actions, error traces, unexpected child processes, and anomalous outbound connections.",
                    "Containment actions: patch affected software, restrict exposure, rotate secrets or sessions if needed, and preserve logs for triage.",
                    "Website-analysis relevance: use URL threat scoring, security header review, TLS checks, and product-specific defensive validation before concluding risk.",
                ]
            )
            documents.append(
                {
                    "doc_key": f"cve-playbook-{vendor}-{product}-{vuln_type}-{counter:04d}",
                    "title": title,
                    "category": "cve-playbook",
                    "source_url": "",
                    "content": content,
                }
            )
            counter += 1
    return documents


def build_website_guides():
    documents = []
    counter = 1
    for finding_key, summary in WEBSITE_FINDINGS:
        for level in ["low", "medium", "high", "critical"]:
            documents.append(
                {
                    "doc_key": f"website-analysis-{finding_key}-{level}-{counter:03d}",
                    "title": f"Website Analysis Guide: {finding_key.replace('-', ' ').title()} ({level.title()})",
                    "category": "website-analysis",
                    "source_url": "",
                    "content": "\n".join(
                        [
                            f"Finding: {finding_key.replace('-', ' ').title()}",
                            f"Severity lens: {level.title()}",
                            f"Summary: {summary}",
                            "Interpretation: use the graphical threat view to decide whether the issue is isolated, repeated, or combined with other baseline weaknesses.",
                            "Analyst explanation: explain the issue in simple language, then connect it to user impact, attacker opportunity, and practical remediation.",
                            "Follow-up: verify whether the issue is expected by design, handled elsewhere, or worth escalating into a site report.",
                        ]
                    ),
                }
            )
            counter += 1
    return documents


def write_output(path, documents):
    path.write_text(json.dumps({"documents": documents}, indent=2), encoding="utf-8")


def main():
    DATA_DIR.mkdir(exist_ok=True)
    write_output(OUTPUT_CVE_PLAYBOOKS, build_cve_playbooks())
    write_output(OUTPUT_WEBSITE_GUIDES, build_website_guides())
    print(f"Wrote {OUTPUT_CVE_PLAYBOOKS}")
    print(f"Wrote {OUTPUT_WEBSITE_GUIDES}")


if __name__ == "__main__":
    main()
