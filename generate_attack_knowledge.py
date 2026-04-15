import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = BASE_DIR / "data" / "cyber_attack_kb.json"


ATTACKS = [
    ("phishing", "Phishing", "email-security", "Fraudulent messages that trick users into revealing credentials or opening malicious links or files.", "Unexpected credential prompts, urgent language, spoofed domains, mismatched links, attachment pressure."),
    ("spear-phishing", "Spear Phishing", "email-security", "Targeted phishing tailored to a specific person, team, or organization.", "Context-rich lure, personalized content, impersonation of internal staff or vendors."),
    ("bec", "Business Email Compromise", "email-security", "Social engineering aimed at fraudulent payments or sensitive business actions.", "Executive impersonation, invoice changes, payment urgency, mailbox-forwarding anomalies."),
    ("credential-stuffing", "Credential Stuffing", "identity-security", "Automated login attempts using reused username/password pairs from previous breaches.", "High login volume across many accounts from few IPs, rapid failures followed by sparse successes."),
    ("password-spraying", "Password Spraying", "identity-security", "Trying a small set of common passwords across many accounts to avoid lockouts.", "One password against many users, low-and-slow failures, broad account distribution."),
    ("brute-force", "Brute Force", "identity-security", "Repeated guessing of credentials for one or more accounts.", "Repeated failures on same account or from same source, increasing velocity, lockout triggers."),
    ("mfa-fatigue", "MFA Fatigue", "identity-security", "Repeated MFA push prompts intended to coerce user approval.", "Burst of push prompts, odd hours, user-approved after many denials."),
    ("token-theft", "Token Theft", "identity-security", "Stealing session or refresh tokens to bypass password/MFA checks.", "Impossible travel with same session, refresh anomalies, sign-ins without password events."),
    ("sqli", "SQL Injection", "application-security", "Injecting SQL syntax into database queries constructed from untrusted input.", "Unexpected SQL errors, quote-based payloads, UNION/OR 1=1 patterns, auth bypass attempts."),
    ("xss", "Cross-Site Scripting", "application-security", "Injecting script into web content viewed by other users.", "Script tags or event handlers in parameters, stored content triggering outbound requests."),
    ("csrf", "Cross-Site Request Forgery", "web-security", "Abusing an authenticated browser to perform unintended actions.", "State-changing requests without CSRF token or origin checks."),
    ("command-injection", "Command Injection", "application-security", "Injecting OS shell syntax into server-side command execution.", "Unexpected shell metacharacters, new process trees, suspicious child processes."),
    ("path-traversal", "Path Traversal", "application-security", "Manipulating file paths to access unintended files.", "Requests containing ../, encoded traversal patterns, sensitive file reads."),
    ("ssrf", "Server-Side Request Forgery", "application-security", "Forcing a server to make requests to unintended internal or external resources.", "Outbound requests to metadata endpoints, internal IPs, odd URL schemes."),
    ("xxe", "XML External Entity", "application-security", "Abusing unsafe XML parsing to read files or reach internal services.", "DOCTYPE/entity payloads, parser errors around external entities, unexpected outbound connections."),
    ("deserialization", "Insecure Deserialization", "application-security", "Unsafe object deserialization leading to code execution or logic abuse.", "Serialized object markers in requests, gadget-chain crashes, unsafe deserializer use."),
    ("rce", "Remote Code Execution", "application-security", "Running attacker-controlled code on a target system.", "Unexpected interpreter processes, web app spawning shells, new services or files."),
    ("priv-esc", "Privilege Escalation", "host-security", "Gaining higher privileges than originally granted.", "Sudo misuse, token abuse, new admin group membership, protected resource access."),
    ("web-shell", "Web Shell", "application-security", "A server-side script that gives attackers remote command capability.", "Tiny newly uploaded scripts, rare POST activity, command execution signatures, odd child processes."),
    ("malware", "Malware", "endpoint-security", "Malicious software used for theft, disruption, or persistence.", "Persistence changes, suspicious startup entries, outbound C2 traffic, tamper attempts."),
    ("ransomware", "Ransomware", "endpoint-security", "Malware that encrypts or locks data for extortion.", "Mass file renames, shadow copy deletion, encryption bursts, ransom note artifacts."),
    ("spyware", "Spyware", "endpoint-security", "Software that covertly collects sensitive information.", "Keylogging behavior, screen capture, unauthorized data exfiltration."),
    ("trojan", "Trojan", "endpoint-security", "Malware disguised as legitimate software or files.", "Execution after lure download, masquerading names, unexpected network beacons."),
    ("worm", "Worm", "network-security", "Self-propagating malware that spreads across systems.", "Rapid lateral spread, repeated exploitation traffic, simultaneous host infections."),
    ("botnet", "Botnet Activity", "network-security", "Compromised hosts controlled as a group for attacks or abuse.", "Periodic beaconing, synchronized traffic, known C2 indicators."),
    ("ddos", "Distributed Denial of Service", "network-security", "Overwhelming a service with traffic or requests.", "Traffic spikes, protocol abuse, resource exhaustion, service degradation."),
    ("mitm", "Man-in-the-Middle", "network-security", "Intercepting or modifying traffic between parties.", "TLS downgrade signs, certificate mismatches, ARP anomalies, proxy insertion."),
    ("dns-spoofing", "DNS Spoofing", "network-security", "Returning forged DNS answers to redirect traffic.", "Unexpected DNS responses, resolver inconsistency, suspicious TTL patterns."),
    ("arp-spoofing", "ARP Spoofing", "network-security", "Poisoning local network ARP caches to intercept traffic.", "MAC changes for same gateway IP, duplicate ARP replies, packet path anomalies."),
    ("dns-tunneling", "DNS Tunneling", "network-security", "Using DNS queries/responses to move data or C2 traffic.", "Long random subdomains, high TXT query volume, unusual entropy, beacon cadence."),
    ("beaconing", "Beaconing", "network-security", "Regular outbound check-ins to attacker-controlled infrastructure.", "Low-and-slow periodic traffic, uniform intervals, repeated domains or IPs."),
    ("data-exfil", "Data Exfiltration", "data-security", "Unauthorized transfer of sensitive data out of the environment.", "Large outbound transfers, rare destinations, compressed/encrypted archives, staging files."),
    ("supply-chain", "Supply Chain Attack", "software-security", "Compromise through dependencies, vendors, or build pipelines.", "Unexpected package updates, signature mismatches, build artifact drift."),
    ("insider-threat", "Insider Threat", "governance", "Malicious or negligent activity by a trusted internal user.", "Access outside role, unusual downloads, after-hours actions, policy bypass."),
    ("cloud-misconfig", "Cloud Misconfiguration Abuse", "cloud-security", "Exposure or compromise caused by insecure cloud settings.", "Public buckets, overly broad IAM, disabled logging, open admin endpoints."),
    ("api-abuse", "API Abuse", "application-security", "Misuse of APIs for scraping, privilege bypass, or resource exhaustion.", "High request burst, missing auth checks, object enumeration, quota evasion."),
]


DETECTION_RULES = [
    ("detect-phishing", "Detecting Phishing", "detection-rules", "Look for urgent language, spoofed sender domains, credential prompts, payment pressure, unexpected attachments, and displayed links that differ from actual destinations."),
    ("detect-credential-stuffing", "Detecting Credential Stuffing", "detection-rules", "Correlate high authentication failure rates across many accounts from limited source IPs, then look for a small number of successes using the same infrastructure."),
    ("detect-password-spraying", "Detecting Password Spraying", "detection-rules", "Alert when the same password pattern or same source hits many usernames with low failure count per user over an extended window."),
    ("detect-bruteforce", "Detecting Brute Force", "detection-rules", "Track repeated authentication failures on the same account, especially when followed by account lockout, MFA prompts, or eventual success."),
    ("detect-mfa-fatigue", "Detecting MFA Fatigue", "detection-rules", "Flag many denied MFA prompts followed by a single approval, especially from new devices or foreign geographies."),
    ("detect-sqli", "Detecting SQL Injection", "detection-rules", "Inspect logs and WAF events for quote-heavy payloads, UNION/SELECT markers, comment operators, OR 1=1 patterns, and sudden SQL parser errors."),
    ("detect-xss", "Detecting XSS", "detection-rules", "Monitor for script tags, event handlers, javascript: URIs, reflected parameters, and outbound browser requests triggered by viewed content."),
    ("detect-ssrf", "Detecting SSRF", "detection-rules", "Alert on server-side outbound requests to metadata endpoints, localhost-like resources, internal ranges, and uncommon schemes requested by user-controlled parameters."),
    ("detect-command-injection", "Detecting Command Injection", "detection-rules", "Correlate user-supplied input containing shell metacharacters with new child processes, shell invocation, or abnormal process lineage."),
    ("detect-path-traversal", "Detecting Path Traversal", "detection-rules", "Search request logs for ../, encoded traversal strings, access to config or passwd-like files, and repeated 403/404 patterns near file endpoints."),
    ("detect-rce", "Detecting Remote Code Execution", "detection-rules", "Alert on web-facing services spawning shells, interpreters, compilers, or network tools unexpectedly, especially after crafted HTTP requests."),
    ("detect-webshell", "Detecting Web Shells", "detection-rules", "Watch for newly written executable scripts in web roots, rare POSTs to small files, and web servers creating child shell processes."),
    ("detect-ransomware", "Detecting Ransomware", "detection-rules", "Detect mass file modifications, extension changes, shadow copy deletion, high entropy writes, and disabling of security controls."),
    ("detect-malware-beaconing", "Detecting Malware Beaconing", "detection-rules", "Look for periodic outbound connections with regular intervals, low data volumes, and repeated destinations or JA3-like fingerprints."),
    ("detect-dns-tunneling", "Detecting DNS Tunneling", "detection-rules", "Identify very long or random-looking subdomains, unusual TXT activity, persistent NXDOMAIN bursts, and high-entropy labels."),
    ("detect-ddos", "Detecting DDoS", "detection-rules", "Measure abnormal traffic spikes, protocol-specific floods, elevated error rates, and saturation of CPU, bandwidth, or connection tables."),
    ("detect-data-exfil", "Detecting Data Exfiltration", "detection-rules", "Flag large outbound transfers, compressed archive creation, movement to rare destinations, and off-hours downloads from sensitive sources."),
    ("detect-insider-threat", "Detecting Insider Threat", "detection-rules", "Correlate unusual data access, broad searches, privilege misuse, removable media use, and after-hours activity by trusted users."),
    ("detect-cloud-abuse", "Detecting Cloud Abuse", "detection-rules", "Audit for public exposure, IAM drift, disabled logging, new access keys, role assumptions, and suspicious API call bursts."),
    ("detect-token-theft", "Detecting Token Theft", "detection-rules", "Look for session reuse from impossible travel locations, browser fingerprint drift, refresh anomalies, and access without normal password events."),
]


def build_documents():
    documents = []
    for key, title, category, summary, indicators in ATTACKS:
        documents.append(
            {
                "doc_key": key,
                "title": title,
                "category": category,
                "source_url": "",
                "content": (
                    f"Attack: {title}\n"
                    f"Summary: {summary}\n"
                    f"Detection signals: {indicators}\n"
                    "Defensive response: validate logs, tighten authentication or access controls, contain affected systems, preserve evidence, and monitor for recurrence."
                ),
            }
        )

    for key, title, category, content in DETECTION_RULES:
        documents.append(
            {
                "doc_key": key,
                "title": title,
                "category": category,
                "source_url": "",
                "content": content,
            }
        )

    documents.append(
        {
            "doc_key": "cyber-attack-taxonomy",
            "title": "Common Cyber Attack Categories",
            "category": "taxonomy",
            "source_url": "",
            "content": "Phishing, spear phishing, business email compromise, credential stuffing, password spraying, brute force, MFA fatigue, token theft, SQL injection, XSS, CSRF, command injection, path traversal, SSRF, XXE, insecure deserialization, RCE, privilege escalation, web shells, malware, ransomware, spyware, trojans, worms, botnets, DDoS, man-in-the-middle, DNS spoofing, ARP spoofing, DNS tunneling, beaconing, data exfiltration, supply chain attacks, insider threats, cloud misconfiguration abuse, and API abuse.",
        }
    )
    return {"documents": documents}


def main():
    OUTPUT_PATH.write_text(json.dumps(build_documents(), indent=2), encoding="utf-8")
    print(f"Wrote {len(build_documents()['documents'])} cybersecurity knowledge docs to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
