import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = BASE_DIR / "data" / "phishing_examples_kb.json"


SCENARIOS = [
    ("payroll", "Payroll account issue"),
    ("vpn", "VPN access problem"),
    ("mailbox", "Mailbox storage warning"),
    ("invoice", "Invoice review needed"),
    ("banking", "Bank verification"),
    ("gift-cards", "Executive gift card request"),
    ("mfa", "Security verification"),
    ("package", "Package delivery notice"),
    ("hr", "HR portal update"),
    ("tax", "Tax form review"),
]

TEMPLATES = [
    "Urgent: your {topic} requires immediate action. Sign in now using this link and confirm your password.",
    "Your {topic} will be suspended today unless you verify your credentials immediately.",
    "Open the attached file to resolve the {topic} problem and log in when prompted.",
    "We detected unusual activity in your {topic}. Re-enter your password and MFA code to secure it.",
    "A senior manager needs you to process the {topic} request within 10 minutes and reply confidentially.",
    "Your {topic} is pending. Use the secure portal below to verify account details now.",
    "Important: the {topic} document was shared with you. Review it and authenticate to continue.",
    "Final warning: your {topic} access expires today. Update credentials to avoid lockout.",
    "The company security team needs you to confirm your {topic} login right away.",
    "Your payment related to {topic} is blocked. Sign in and confirm your details now.",
]


def build_documents():
    documents = []
    idx = 1
    for slug, topic in SCENARIOS:
        for template in TEMPLATES:
            documents.append(
                {
                    "doc_key": f"phishing-example-{idx}",
                    "title": f"Phishing Example {idx}",
                    "category": "phishing-examples",
                    "source_url": "",
                    "content": (
                        f"Classification: Phishing\n"
                        f"Scenario: {topic}\n"
                        f"Example text: {template.format(topic=topic)}\n"
                        "Red flags: urgency, credential request, unexpected link or attachment, pressure to bypass normal process."
                    ),
                }
            )
            idx += 1
    return {"documents": documents}


def main():
    data = build_documents()
    OUTPUT_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Wrote {len(data['documents'])} phishing examples to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
