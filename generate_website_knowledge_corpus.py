import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_JSON = BASE_DIR / "data" / "website_risk_corpus_kb.json"

RISK_THEMES = [
    "header posture",
    "cookie posture",
    "tls renewal",
    "redirect hygiene",
    "server fingerprint exposure",
    "cors exposure",
    "clickjacking posture",
]

SECTORS = [
    "retail",
    "banking",
    "media",
    "travel",
    "education",
    "saas",
    "healthcare",
]

SEVERITIES = ["low", "medium", "high", "critical"]


def build_doc(index):
    theme = RISK_THEMES[index % len(RISK_THEMES)]
    sector = SECTORS[index % len(SECTORS)]
    severity = SEVERITIES[index % len(SEVERITIES)]
    return {
        "doc_key": f"website-risk-corpus-{index:04d}",
        "title": f"Website Risk Playbook {index}: {theme.title()} for {sector.title()}",
        "category": "website-risk-corpus",
        "source_url": "",
        "content": (
            f"Sector: {sector}\n"
            f"Theme: {theme}\n"
            f"Risk level: {severity}\n"
            f"User explanation: This pattern helps explain {theme} issues on public websites in simple language.\n"
            f"How to describe it: focus on what the visitor sees, what is exposed, and what should be fixed first.\n"
            f"What to check: response headers, visible cookies, redirect behavior, TLS age, and public disclosure clues.\n"
            f"What to say: summarize good controls, visible risks, and first remediation steps without exploit detail.\n"
            f"Fix guidance: improve headers, reduce exposure, tighten cookie handling, and patch product-specific software where relevant."
        ),
    }


def main():
    docs = [build_doc(index) for index in range(1, 3501)]
    OUTPUT_JSON.write_text(json.dumps({"documents": docs}, indent=2), encoding="utf-8")
    print(f"Wrote {len(docs)} website risk knowledge docs to {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
