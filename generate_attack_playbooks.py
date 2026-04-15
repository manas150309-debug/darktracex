import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = BASE_DIR / "data" / "attack_playbooks_kb.json"


ATTACKS = [
    ("phishing", "Phishing", "email-security"),
    ("spear-phishing", "Spear Phishing", "email-security"),
    ("bec", "Business Email Compromise", "email-security"),
    ("credential-stuffing", "Credential Stuffing", "identity-security"),
    ("password-spraying", "Password Spraying", "identity-security"),
    ("brute-force", "Brute Force", "identity-security"),
    ("mfa-fatigue", "MFA Fatigue", "identity-security"),
    ("token-theft", "Token Theft", "identity-security"),
    ("sql-injection", "SQL Injection", "application-security"),
    ("xss", "Cross-Site Scripting", "application-security"),
    ("csrf", "Cross-Site Request Forgery", "web-security"),
    ("command-injection", "Command Injection", "application-security"),
    ("path-traversal", "Path Traversal", "application-security"),
    ("ssrf", "Server-Side Request Forgery", "application-security"),
    ("xxe", "XML External Entity", "application-security"),
    ("insecure-deserialization", "Insecure Deserialization", "application-security"),
    ("rce", "Remote Code Execution", "application-security"),
    ("privilege-escalation", "Privilege Escalation", "host-security"),
    ("web-shell", "Web Shell", "application-security"),
    ("malware", "Malware", "endpoint-security"),
    ("ransomware", "Ransomware", "endpoint-security"),
    ("spyware", "Spyware", "endpoint-security"),
    ("trojan", "Trojan", "endpoint-security"),
    ("worm", "Worm", "network-security"),
    ("botnet", "Botnet Activity", "network-security"),
    ("ddos", "Distributed Denial of Service", "network-security"),
    ("mitm", "Man-in-the-Middle", "network-security"),
    ("dns-spoofing", "DNS Spoofing", "network-security"),
    ("arp-spoofing", "ARP Spoofing", "network-security"),
    ("dns-tunneling", "DNS Tunneling", "network-security"),
    ("beaconing", "Beaconing", "network-security"),
    ("data-exfiltration", "Data Exfiltration", "data-security"),
    ("supply-chain", "Supply Chain Attack", "software-security"),
    ("insider-threat", "Insider Threat", "governance"),
    ("cloud-misconfig", "Cloud Misconfiguration Abuse", "cloud-security"),
    ("api-abuse", "API Abuse", "application-security"),
]


PLAYBOOK_SECTIONS = [
    (
        "overview",
        "Overview",
        "Definition: {title} is a common cybersecurity threat in the {category} area. Analyst goal: identify scope, affected assets, and immediate containment priorities."
    ),
    (
        "detection-signals",
        "Detection Signals",
        "Primary detection signals for {title}: authentication anomalies, suspicious request patterns, unusual process or network behavior, and deviations from the normal user or service baseline."
    ),
    (
        "triage-questions",
        "Triage Questions",
        "Triage questions for {title}: when did it start, which assets are affected, which identities were involved, what telemetry confirms it, and whether containment can be applied without losing evidence."
    ),
    (
        "log-patterns",
        "Log Patterns",
        "Useful log patterns for {title}: repeated failures, low-and-slow retries, odd user-agents, unusual status codes, process lineage anomalies, rare destinations, and event bursts near high-risk actions."
    ),
    (
        "containment",
        "Containment",
        "Containment steps for {title}: isolate impacted accounts or hosts, block malicious indicators, disable risky paths, preserve logs, and stop further spread while minimizing business disruption."
    ),
    (
        "eradication",
        "Eradication",
        "Eradication guidance for {title}: remove malicious artifacts, revoke exposed credentials or tokens, patch the exploited weakness, re-image if trust is lost, and validate that persistence is gone."
    ),
    (
        "recovery",
        "Recovery",
        "Recovery steps for {title}: restore clean state, rotate secrets, validate monitoring coverage, test critical workflows, and watch for recurrence during a defined observation window."
    ),
    (
        "prevention",
        "Prevention",
        "Prevention guidance for {title}: least privilege, secure defaults, MFA where relevant, logging, segmentation, validated input handling, patching, and user or admin awareness controls."
    ),
    (
        "false-positives",
        "False Positives",
        "False-positive review for {title}: compare against expected admin activity, known scanners, test automation, maintenance windows, and approved third-party integrations before escalation."
    ),
    (
        "siem-hunt",
        "SIEM Hunt",
        "Hunt hypothesis for {title}: search for clustered indicators across identity, endpoint, and network telemetry, then pivot by host, user, IP, process, or destination to map the full timeline."
    ),
]


def build_documents():
    documents = []
    for slug, title, category in ATTACKS:
        for section_slug, section_title, template in PLAYBOOK_SECTIONS:
            documents.append(
                {
                    "doc_key": f"{slug}-{section_slug}",
                    "title": f"{title} {section_title}",
                    "category": "playbooks",
                    "source_url": "",
                    "content": template.format(title=title, category=category),
                }
            )
    return {"documents": documents}


def main():
    data = build_documents()
    OUTPUT_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Wrote {len(data['documents'])} attack playbook docs to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
