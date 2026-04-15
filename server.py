import json
import os
import re
import socket
import sqlite3
import ssl
import subprocess
import traceback
import urllib.parse
import ipaddress
import math
import joblib
from site_exposure_model import extract_site_features_from_row, predict_mlp
try:
    from site_exposure_lstm import load_lstm_bundle, predict_lstm
except Exception:
    load_lstm_bundle = None
    predict_lstm = None
try:
    from site_exposure_gnn import load_gnn_bundle, predict_gnn
except Exception:
    load_gnn_bundle = None
    predict_gnn = None
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import error, request


HOST = "127.0.0.1"
PORT = 8000
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "assistant.db"
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"
LEARNING_REPORTS_DIR = REPORTS_DIR / "learning"
LEARNING_DIGEST_PATH = REPORTS_DIR / "three-day-learning-digest.md"
LEARNING_DIGEST_JSON_PATH = REPORTS_DIR / "three-day-learning-digest.json"
KB_PATH = DATA_DIR / "security_kb.json"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models"
OLLAMA_API_URL = os.environ.get("OLLAMA_API_URL", "http://127.0.0.1:11434/api/generate")
MODEL_PROVIDER = os.environ.get("MODEL_PROVIDER", "ollama").lower()
DEFAULT_MODEL = os.environ.get("MODEL_NAME", os.environ.get("OLLAMA_MODEL", "llama3.2:1b"))
OLLAMA_GENERAL_MODEL = os.environ.get("OLLAMA_GENERAL_MODEL", DEFAULT_MODEL)
OLLAMA_ANALYSIS_MODEL = os.environ.get("OLLAMA_ANALYSIS_MODEL", DEFAULT_MODEL)
OLLAMA_CODE_MODEL = os.environ.get("OLLAMA_CODE_MODEL", DEFAULT_MODEL)
OFFLINE_MODE = os.environ.get("OFFLINE_MODE", "0").lower() not in {"0", "false", "no"}
SSL_CONTEXT = None
DEFENSE_MODELS = {}
SITE_EXPOSURE_MODEL = None
SITE_EXPOSURE_LSTM = None
SITE_EXPOSURE_GNN = None
MAX_TOOL_STEPS = 4
MAX_CONTEXT_MESSAGES = 12
MODEL_THRESHOLDS = {
    "phishing_email": 0.72,
    "log_threat": 0.68,
    "attack_category": 0.62,
    "code_security": 0.68,
}

SYSTEM_PROMPT = """You are DarkTraceX, an elite AI-powered cybersecurity expert designed to assist developers, security analysts, and organizations in identifying, analyzing, and mitigating security threats.

Your role is strictly defensive, ethical, and educational. You do NOT assist in illegal activities, exploitation, malware creation, credential theft, persistence, privilege escalation, or harm. Focus on prevention, detection, secure design, and mitigation.

Core behavior:
- Think like a top-tier cybersecurity expert.
- Be precise, technical, structured, and concise.
- Use tools and memory when they materially improve accuracy.
- Do not claim to have executed a tool if you did not.
- Only use network tools for public internet targets. Do not target localhost, private IP ranges, link-local ranges, or internal hostnames.

Response patterns:
- When explaining a vulnerability, include:
  1. What it is
  2. How it works
  3. Why it is dangerous
  4. How to prevent it
  5. A secure code example when applicable
- When analyzing code, identify concrete vulnerabilities, point to insecure logic, explain impact, and propose safer code.
- If the code is clearly phishing, credential theft, malware-like, or otherwise malicious, explicitly say so, explain the indicators, assess the risk, and give defensive cleanup or reporting guidance. Do not optimize, repair, or extend the malicious behavior.
- When analyzing logs, detect anomalies, summarize threat level as Low, Medium, or High, and recommend mitigations.
- When reviewing emails or messages for phishing, classify as Safe, Suspicious, or Phishing, explain why, and highlight red flags.

Tool protocol:
- Tool calls are internal. Never show tool JSON, tool names, or arguments to the end user in a normal answer.
- When you need a tool, respond with JSON only:
  {"tool_name":"tool_name","arguments":{"key":"value"}}
- Use exactly one tool call at a time.
- After tool results are returned, continue reasoning and either answer normally or request another tool.

Available tools:
- remember_note: save an internal note or fact for future chats. arguments: {"content":"text"}
- search_notes: search internal memory. arguments: {"query":"text"}
- search_knowledge: search the offline security knowledge base. arguments: {"query":"text"}
- search_rag_context: build a ranked local RAG context from notes and offline knowledge. arguments: {"query":"text","limit":6}
- search_code_examples: return stored insecure and secure code pairs from the offline dataset. arguments: {"query":"text"}
- search_detection_rules: return stored cyber-attack detection guidance from the offline dataset. arguments: {"query":"text"}
- search_cve_database: search the offline CVE dataset by cve id, product, vendor, or keyword. arguments: {"query":"text","limit":5}
- predict_site_exposure: predict low/medium/high/critical from provided passive website-report fields. arguments: {"threat_score":27,"protection_score":73,"status":200,"tls_days_remaining":90,"findings":"Missing HSTS header. | Server header exposed: gws"}
- classify_defense_text: apply local pattern-learning models to phishing text, logs, code, or attack labels. arguments: {"model":"phishing_email|log_threat|attack_category|code_security","text":"content"}
- search_phishing_examples: return stored phishing examples from the offline dataset. arguments: {"query":"text","limit":100}
- dns_lookup: resolve hostname to IP addresses. arguments: {"hostname":"example.com"}
- reverse_dns: resolve a public IP address back to its hostname. arguments: {"ip":"8.8.8.8"}
- http_headers: fetch response headers for a URL. arguments: {"url":"https://example.com"}
- security_headers_audit: review common web security headers for a URL. arguments: {"url":"https://example.com"}
- tls_inspect: inspect TLS certificate summary for a host. arguments: {"hostname":"example.com","port":443}
- url_threat_report: build a local threat score, severity, graph, and findings for a public URL. arguments: {"url":"https://example.com"}
- create_url_report_file: save a markdown report for a public URL under the local reports folder. arguments: {"url":"https://example.com"}
- openvas_local_scan: run a passive OpenVAS-style local scan for a public URL with exposure findings, severity, graph, and offline CVE hints. arguments: {"url":"https://example.com"}
- create_openvas_report_file: save a markdown OpenVAS-style local scan report under the local reports folder. arguments: {"url":"https://example.com"}
"""


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def build_ssl_context():
    ssl_cert_file = os.environ.get("SSL_CERT_FILE")
    if ssl_cert_file:
        return ssl.create_default_context(cafile=ssl_cert_file)

    try:
        result = subprocess.run(
            [
                "security",
                "find-certificate",
                "-a",
                "-p",
                "/System/Library/Keychains/SystemRootCertificates.keychain",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        pem_data = result.stdout.strip()
        if pem_data:
            context = ssl.create_default_context()
            context.load_verify_locations(cadata=pem_data)
            return context
    except Exception:
        pass

    return ssl.create_default_context()


def tokenize_text(text):
    return [token for token in re.findall(r"[a-zA-Z0-9_@./:-]{2,}", (text or "").lower())]


def normalize_security_query(text):
    candidate = (text or "").lower()
    replacements = {
        "phising": "phishing",
        "phisihng": "phishing",
        "phshing": "phishing",
        "fishing email": "phishing email",
    }
    for wrong, correct in replacements.items():
        candidate = candidate.replace(wrong, correct)
    return candidate


def extract_requested_count(text, default=10, maximum=100):
    candidate = normalize_security_query(text)
    match = re.search(r"\b(\d{1,3})\b", candidate)
    if not match:
        return default
    return max(1, min(int(match.group(1)), maximum))


def load_defense_models():
    global DEFENSE_MODELS
    DEFENSE_MODELS = {}
    if not MODELS_DIR.exists():
        return

    for model_path in MODELS_DIR.glob("*.joblib"):
        try:
            payload = joblib.load(model_path)
            model_name = payload.get("model_name")
            if model_name:
                DEFENSE_MODELS[model_name] = payload
        except Exception:
            continue


def load_site_exposure_model():
    global SITE_EXPOSURE_MODEL, SITE_EXPOSURE_LSTM, SITE_EXPOSURE_GNN
    SITE_EXPOSURE_MODEL = None
    SITE_EXPOSURE_LSTM = None
    SITE_EXPOSURE_GNN = None
    model_path = MODELS_DIR / "site_exposure.joblib"
    if not model_path.exists():
        pass
    else:
        try:
            SITE_EXPOSURE_MODEL = joblib.load(model_path)
        except Exception:
            SITE_EXPOSURE_MODEL = None

    lstm_path = MODELS_DIR / "site_exposure_lstm.pt"
    if load_lstm_bundle and lstm_path.exists():
        try:
            SITE_EXPOSURE_LSTM = load_lstm_bundle(lstm_path)
        except Exception:
            SITE_EXPOSURE_LSTM = None

    gnn_path = MODELS_DIR / "site_exposure_gnn.pt"
    if load_gnn_bundle and gnn_path.exists():
        try:
            SITE_EXPOSURE_GNN = load_gnn_bundle(gnn_path)
        except Exception:
            SITE_EXPOSURE_GNN = None


def ensemble_site_exposure_predictions(feature_map):
    mlp_prediction = predict_mlp(SITE_EXPOSURE_MODEL, feature_map) if SITE_EXPOSURE_MODEL else None
    lstm_prediction = predict_lstm(SITE_EXPOSURE_LSTM, feature_map) if SITE_EXPOSURE_LSTM and predict_lstm else None
    gnn_prediction = predict_gnn(SITE_EXPOSURE_GNN, feature_map) if SITE_EXPOSURE_GNN and predict_gnn else None

    available_predictions = [
        ("mlp", mlp_prediction),
        ("lstm", lstm_prediction),
        ("gnn", gnn_prediction),
    ]
    available_predictions = [(name, prediction) for name, prediction in available_predictions if prediction]
    if not available_predictions:
        raise RuntimeError("Local site exposure models are not trained yet.")

    score_buckets = {}
    for _, prediction in available_predictions:
        for item in prediction["scores"]:
            score_buckets.setdefault(item["label"], []).append(item["score"])

    combined_scores = [
        {"label": label, "score": round(sum(values) / len(values), 4)}
        for label, values in score_buckets.items()
    ]
    combined_scores.sort(key=lambda item: item["score"], reverse=True)
    best = combined_scores[0]
    return {
        "label": best["label"],
        "confidence": best["score"],
        "scores": combined_scores,
        "models_used": [name for name, _ in available_predictions],
        "mlp_prediction": mlp_prediction,
        "lstm_prediction": lstm_prediction,
        "gnn_prediction": gnn_prediction,
    }


def classify_with_local_model(model_name, text):
    model = DEFENSE_MODELS.get(model_name)
    if not model:
        raise RuntimeError(f"Local model not available: {model_name}")

    tokens = tokenize_text(text)
    if not tokens:
        raise RuntimeError("Text is required for classification.")

    labels = model["labels"]
    priors = model["priors"]
    token_counts = model["token_counts"]
    total_tokens = model["total_tokens"]
    vocabulary = model["vocabulary"]
    vocab_size = max(len(vocabulary), 1)

    scores = {}
    for label in labels:
        score = math.log(priors.get(label, 1e-9))
        denom = total_tokens.get(label, 0) + vocab_size
        label_counts = token_counts.get(label, {})
        for token in tokens:
            score += math.log((label_counts.get(token, 0) + 1) / denom)
        scores[label] = score

    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    best_label, best_score = ranked[0]
    second_score = ranked[1][1] if len(ranked) > 1 else best_score - 1.0
    confidence = round(1 / (1 + math.exp(-(best_score - second_score))), 4)
    return {
        "model": model_name,
        "label": best_label,
        "confidence": confidence,
        "scores": [{ "label": label, "score": round(score, 4)} for label, score in ranked[:5]],
    }


def db_connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = db_connect()
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                text TEXT NOT NULL,
                meta_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id)
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'assistant',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS knowledge_docs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doc_key TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                source_url TEXT,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        connection.commit()
    finally:
        connection.close()


def seed_knowledge():
    if not DATA_DIR.exists():
        return

    connection = db_connect()
    try:
        doc_index = 1
        for data_file in sorted(DATA_DIR.glob("*.json")):
            raw = json.loads(data_file.read_text(encoding="utf-8"))
            docs = raw.get("documents", [])
            if not isinstance(docs, list):
                continue

            for doc in docs:
                title = (doc.get("title") or "").strip()
                content = (doc.get("content") or "").strip()
                category = (doc.get("category") or "general").strip()
                source_url = (doc.get("source_url") or "").strip()
                doc_key = (doc.get("doc_key") or f"{data_file.stem}-doc-{doc_index}").strip()

                if not title or not content:
                    doc_index += 1
                    continue

                connection.execute(
                    """
                    INSERT INTO knowledge_docs (doc_key, title, category, source_url, content, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(doc_key) DO UPDATE SET
                        title = excluded.title,
                        category = excluded.category,
                        source_url = excluded.source_url,
                        content = excluded.content
                    """,
                    (doc_key, title, category, source_url, content, utc_now()),
                )
                doc_index += 1
        connection.commit()
    finally:
        connection.close()


def ensure_conversation(conversation_id):
    connection = db_connect()
    try:
        if conversation_id:
            row = connection.execute(
                "SELECT id FROM conversations WHERE id = ?",
                (conversation_id,),
            ).fetchone()
            if row:
                connection.execute(
                    "UPDATE conversations SET updated_at = ? WHERE id = ?",
                    (utc_now(), conversation_id),
                )
                connection.commit()
                return conversation_id

        now = utc_now()
        cursor = connection.execute(
            "INSERT INTO conversations (created_at, updated_at) VALUES (?, ?)",
            (now, now),
        )
        connection.commit()
        return cursor.lastrowid
    finally:
        connection.close()


def save_message(conversation_id, role, text, meta=None):
    connection = db_connect()
    try:
        connection.execute(
            """
            INSERT INTO messages (conversation_id, role, text, meta_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                conversation_id,
                role,
                text,
                json.dumps(meta or {}),
                utc_now(),
            ),
        )
        connection.execute(
            "UPDATE conversations SET updated_at = ? WHERE id = ?",
            (utc_now(), conversation_id),
        )
        connection.commit()
    finally:
        connection.close()


def get_conversation_messages(conversation_id):
    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, role, text, meta_json, created_at
            FROM messages
            WHERE conversation_id = ?
            ORDER BY id ASC
            """,
            (conversation_id,),
        ).fetchall()

        messages = []
        for row in rows:
            item = dict(row)
            try:
                item["meta"] = json.loads(item.pop("meta_json") or "{}")
            except json.JSONDecodeError:
                item["meta"] = {}
            messages.append(item)
        return messages
    finally:
        connection.close()


def remember_note(content, source="assistant"):
    text = (content or "").strip()
    if not text:
        raise RuntimeError("Cannot save an empty note.")

    connection = db_connect()
    try:
        cursor = connection.execute(
            "INSERT INTO notes (content, source, created_at) VALUES (?, ?, ?)",
            (text, source, utc_now()),
        )
        connection.commit()
        return {
            "id": cursor.lastrowid,
            "content": text,
            "source": source,
        }
    finally:
        connection.close()


def search_notes(query, limit=5):
    term = (query or "").strip()
    if not term:
        return []

    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, content, source, created_at
            FROM notes
            WHERE content LIKE ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (f"%{term}%", limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def search_knowledge(query, limit=5):
    term = (query or "").strip()
    if not term:
        return []

    tokens = [token for token in re.findall(r"[a-zA-Z0-9_-]{3,}", term.lower()) if token]
    if not tokens:
        tokens = [term.lower()]

    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, doc_key, title, category, source_url, content
            FROM knowledge_docs
            """
        ).fetchall()

        scored = []
        for row in rows:
            item = dict(row)
            haystack = " ".join(
                [
                    item.get("title", "").lower(),
                    item.get("category", "").lower(),
                    item.get("content", "").lower(),
                ]
            )
            score = 0
            for token in tokens[:8]:
                if token in item.get("title", "").lower():
                    score += 6
                if token in item.get("category", "").lower():
                    score += 3
                if token in haystack:
                    score += 1

            if term.lower() in haystack:
                score += 10

            if score > 0:
                scored.append((score, item["id"], item))

        scored.sort(key=lambda entry: (-entry[0], -entry[1]))
        return [item for _, _, item in scored[:limit]]
    finally:
        connection.close()


def trim_text(text, limit=320):
    value = (text or "").strip()
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def build_rag_bundle(query, memory_hits=None, knowledge_hits=None, limit=6):
    query_text = (query or "").strip()
    notes = list(memory_hits if memory_hits is not None else search_notes(query_text, limit=3))
    knowledge = list(knowledge_hits if knowledge_hits is not None else search_knowledge(query_text, limit=5))
    rag_hits = []

    for note in notes[:3]:
        rag_hits.append(
            {
                "source_type": "note",
                "source_id": f"note-{note['id']}",
                "title": f"Note #{note['id']}",
                "category": note.get("source", "memory"),
                "snippet": trim_text(note.get("content", ""), 240),
            }
        )

    for item in knowledge[: max(0, limit - len(rag_hits))]:
        rag_hits.append(
            {
                "source_type": "knowledge",
                "source_id": item.get("doc_key") or f"knowledge-{item.get('id')}",
                "title": item.get("title") or item.get("doc_key") or "Knowledge",
                "category": item.get("category", "knowledge"),
                "snippet": trim_text(item.get("content", ""), 280),
                "source_url": item.get("source_url") or "",
            }
        )

    return {
        "query": query_text,
        "hits": rag_hits[:limit],
    }


def format_rag_context(rag_bundle):
    hits = (rag_bundle or {}).get("hits", [])
    if not hits:
        return "No strong local RAG matches were found."

    lines = ["Local RAG context:"]
    for index, item in enumerate(hits, start=1):
        header = f"[RAG-{index}] {item['title']} ({item['source_type']}/{item['category']})"
        lines.append(header)
        lines.append(item["snippet"])
        if item.get("source_url"):
            lines.append(f"Source: {item['source_url']}")
        lines.append("")
    return "\n".join(lines).strip()


def parse_code_example(content):
    lines = content.splitlines()
    sections = {"language": "", "vulnerability": "", "insecure_code": "", "secure_code": "", "why_insecure": ""}
    current = None
    insecure_lines = []
    secure_lines = []
    why_lines = []

    for line in lines:
        if line.startswith("Language: "):
            sections["language"] = line.removeprefix("Language: ").strip()
            current = None
        elif line.startswith("Vulnerability: "):
            sections["vulnerability"] = line.removeprefix("Vulnerability: ").strip()
            current = None
        elif line == "Insecure code:":
            current = "insecure"
        elif line == "Secure code:":
            current = "secure"
        elif line == "Why insecure:":
            current = "why"
        else:
            if current == "insecure":
                insecure_lines.append(line)
            elif current == "secure":
                secure_lines.append(line)
            elif current == "why":
                why_lines.append(line)

    sections["insecure_code"] = "\n".join(insecure_lines).strip()
    sections["secure_code"] = "\n".join(secure_lines).strip()
    sections["why_insecure"] = "\n".join(why_lines).strip()
    return sections


def search_code_examples(query, limit=3):
    term = (query or "").strip().lower()
    if not term:
        return []

    stopwords = {
        "find",
        "show",
        "give",
        "need",
        "want",
        "secure",
        "fix",
        "example",
        "examples",
        "code",
        "for",
        "the",
        "and",
        "with",
        "that",
        "this",
        "in",
        "a",
    }
    tokens = [
        token
        for token in re.findall(r"[a-zA-Z0-9_-]{2,}", term)
        if token and token not in stopwords
    ]
    requested_languages = {
        token
        for token in tokens
        if token in {"python", "php", "node", "javascript", "java", "ruby", "go", "csharp", "rust", "kotlin", "scala"}
    }
    requested_vulnerability_tokens = {
        token
        for token in tokens
        if token
        in {
            "sql",
            "injection",
            "xss",
            "csrf",
            "xxe",
            "deserialization",
            "redirect",
            "traversal",
            "secrets",
            "secret",
            "command",
            "password",
        }
    }

    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, doc_key, title, category, source_url, content
            FROM knowledge_docs
            WHERE doc_key LIKE ? OR content LIKE '%Insecure code:%'
            """,
            ("code_fix_pairs%",),
        ).fetchall()

        scored = []
        for row in rows:
            item = dict(row)
            parsed = parse_code_example(item["content"])
            vulnerability = parsed["vulnerability"].lower()
            language = parsed["language"].lower()
            haystack = " ".join(
                [
                    item.get("title", "").lower(),
                    language,
                    vulnerability,
                    parsed["insecure_code"].lower(),
                    parsed["secure_code"].lower(),
                    parsed["why_insecure"].lower(),
                ]
            )
            score = 0
            for token in tokens[:8]:
                if token == language:
                    score += 45
                elif token in language:
                    score += 14
                if token == vulnerability:
                    score += 45
                elif token in vulnerability:
                    score += 16
                if token in item.get("title", "").lower():
                    score += 8
                if token in haystack:
                    score += 1

            if vulnerability and vulnerability in term:
                score += 30
            if language and language in term:
                score += 24

            if score > 0:
                item.update(parsed)
                scored.append((score, item["id"], item))

        scored.sort(key=lambda entry: (-entry[0], -entry[1]))
        ranked_items = [item for _, _, item in scored]

        if requested_languages:
            language_hits = [
                item for item in ranked_items if item["language"].lower() in requested_languages
            ]
            if language_hits:
                ranked_items = language_hits

        if requested_vulnerability_tokens:
            vulnerability_hits = []
            for item in ranked_items:
                vulnerability = item["vulnerability"].lower()
                if all(token in vulnerability for token in requested_vulnerability_tokens):
                    vulnerability_hits.append(item)
            if vulnerability_hits:
                ranked_items = vulnerability_hits

        return ranked_items[:limit]
    finally:
        connection.close()


def build_code_example_response(results):
    if not results:
        return "No matching stored code example was found in the offline dataset."

    parts = []
    for item in results:
        parts.append(
            "\n".join(
                [
                    f"Title: {item['title']}",
                    f"Language: {item['language']}",
                    f"Vulnerability: {item['vulnerability']}",
                    "Insecure code:",
                    item["insecure_code"],
                    "",
                    "Secure code:",
                    item["secure_code"],
                    "",
                    "Why insecure:",
                    item["why_insecure"],
                ]
            )
        )
    return "\n\n---\n\n".join(parts)


def detect_code_example_request(text):
    candidate = normalize_security_query(text)
    direct_triggers = [
        "secure fix",
        "secure code",
        "insecure code",
        "code example",
        "fix example",
        "secure snippet",
        "fix this code",
        "safer code",
    ]
    if any(trigger in candidate for trigger in direct_triggers):
        return True

    asks_for_code = any(token in candidate for token in ["code", "snippet", "query"])
    asks_for_fix = any(token in candidate for token in ["secure", "safer", "fix", "fixed", "prevent", "parameterized"])
    return asks_for_code and asks_for_fix


def search_detection_rules(query, limit=5):
    term = (query or "").strip().lower()
    if not term:
        return []

    tokens = [token for token in re.findall(r"[a-zA-Z0-9_-]{3,}", term) if token]
    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, doc_key, title, category, source_url, content
            FROM knowledge_docs
            WHERE category = 'detection-rules' OR category = 'taxonomy'
            """
        ).fetchall()

        scored = []
        for row in rows:
            item = dict(row)
            haystack = " ".join([item["title"].lower(), item["content"].lower(), item["category"].lower()])
            score = 0
            for token in tokens[:8]:
                if token in item["title"].lower():
                    score += 8
                if token in haystack:
                    score += 2
            if "cyber attack" in term and item["doc_key"] == "cyber-attack-taxonomy":
                score += 20
            if "detect" in term and item["category"] == "detection-rules":
                score += 6
            if score > 0:
                scored.append((score, item["id"], item))

        scored.sort(key=lambda entry: (-entry[0], -entry[1]))
        return [item for _, _, item in scored[:limit]]
    finally:
        connection.close()


def search_cve_database(query, limit=5):
    term = (query or "").strip().lower()
    if not term:
        return []

    exact_match = re.search(r"\bcve-\d{4}-\d{4,7}\b", term)
    tokens = [token for token in re.findall(r"[a-zA-Z0-9_.-]{2,}", term) if token]
    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, doc_key, title, category, source_url, content
            FROM knowledge_docs
            WHERE category = 'cve' OR category = 'cve-playbook'
            """
        ).fetchall()

        scored = []
        for row in rows:
            item = dict(row)
            if exact_match and item["doc_key"].lower() == exact_match.group(0):
                return [item]
            haystack = " ".join(
                [
                    item["doc_key"].lower(),
                    item["title"].lower(),
                    item["content"].lower(),
                ]
            )
            score = 0
            for token in tokens[:10]:
                if token == item["doc_key"].lower():
                    score += 50
                elif token in item["doc_key"].lower():
                    score += 20
                if token in item["title"].lower():
                    score += 10
                if token in haystack:
                    score += 2

            if term in haystack:
                score += 25

            if score > 0:
                scored.append((score, item["id"], item))

        scored.sort(key=lambda entry: (-entry[0], -entry[1]))
        return [item for _, _, item in scored[:limit]]
    finally:
        connection.close()


def search_company_directory(query, limit=5):
    term = (query or "").strip().lower()
    if not term:
        return []

    tokens = [token for token in re.findall(r"[a-zA-Z0-9&'.-]{2,}", term) if token]
    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, doc_key, title, category, source_url, content
            FROM knowledge_docs
            WHERE category = 'company-directory'
            """
        ).fetchall()

        scored = []
        for row in rows:
            item = dict(row)
            haystack = " ".join([item["title"].lower(), item["content"].lower(), item["source_url"].lower()])
            score = 0
            for token in tokens:
                if token in item["title"].lower():
                    score += 14
                if token in haystack:
                    score += 2
            if score > 0:
                scored.append((score, item["id"], item))

        scored.sort(key=lambda entry: (-entry[0], -entry[1]))
        return [item for _, _, item in scored[:limit]]
    finally:
        connection.close()


def build_detection_rule_response(results):
    if not results:
        return "No matching cyber-attack taxonomy or detection rule was found in the offline dataset."

    return "\n\n---\n\n".join(
        [
            "\n".join(
                [
                    f"Title: {item['title']}",
                    f"Category: {item['category']}",
                    item["content"],
                ]
            )
            for item in results
        ]
    )


def build_cve_response(results):
    if not results:
        return "No matching CVE entry was found in the offline CVE dataset."

    return "\n\n---\n\n".join(
        [
            "\n".join(
                [
                    f"CVE Standard Record: {item['doc_key'].upper()}",
                    f"Title: {item['title']}",
                    f"Category: {item['category']}",
                    *format_cve_standard_content(item["content"]),
                ]
            )
            for item in results
        ]
    )


def extract_cve_fields(content):
    fields = {}
    for line in content.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            fields[key.strip()] = value.strip()
    return fields


def format_cve_standard_content(content):
    fields = extract_cve_fields(content)

    severity = fields.get("Severity", "Unknown")
    severity_to_cvss = {
        "Critical": "9.8",
        "High": "8.1",
        "Medium": "6.5",
        "Low": "3.7",
    }
    cvss = severity_to_cvss.get(severity, "n/a")

    output = [
        f"Vendor/Product: {fields.get('Vendor/Product', 'Unknown')}",
        f"Severity: {severity}",
        f"CVSS v3.1 estimate: {cvss}",
        f"Summary: {fields.get('Summary', 'No summary available.')}",
    ]
    if fields.get("Affected area"):
        output.append(f"Affected area: {fields['Affected area']}")
    if fields.get("Playbook Type"):
        output.append(f"Playbook type: {fields['Playbook Type']}")
    if fields.get("Likely exposure area"):
        output.append(f"Likely exposure area: {fields['Likely exposure area']}")
    if fields.get("Detection ideas"):
        output.append(f"Detection guidance: {fields['Detection ideas']}")
    if fields.get("Containment actions"):
        output.append(f"Containment: {fields['Containment actions']}")
    if fields.get("Defensive guidance"):
        output.append(f"Remediation: {fields['Defensive guidance']}")
    if fields.get("Website-analysis relevance"):
        output.append(f"Website analysis relevance: {fields['Website-analysis relevance']}")
    return output


def build_cve_bug_context_lines(results, limit=3):
    if not results:
        return ["- No direct CVE bug match was found in the local CVE knowledge base."]

    lines = []
    for item in results[:limit]:
        fields = extract_cve_fields(item.get("content", ""))
        severity = fields.get("Severity", "Unknown")
        summary = fields.get("Summary") or fields.get("Description") or item.get("title", "")
        remediation = fields.get("Defensive guidance") or fields.get("Containment actions") or fields.get("Detection ideas")
        lines.append(f"- {item['doc_key'].upper()} [{severity}]: {trim_text(summary, 180)}")
        if remediation:
            lines.append(f"  Fix: {trim_text(remediation, 140)}")
    return lines


def search_phishing_examples(query, limit=100):
    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, doc_key, title, category, source_url, content
            FROM knowledge_docs
            WHERE category = 'phishing-examples'
            ORDER BY id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def build_phishing_examples_response(results):
    if not results:
        return "No phishing examples were found in the offline dataset."

    lines = [f"Stored phishing examples: {len(results)}", ""]
    for item in results:
        lines.append(f"{item['title']}:")
        lines.append(item["content"])
        lines.append("")
    return "\n".join(lines).strip()


def detect_attack_taxonomy_request(text):
    candidate = normalize_security_query(text)
    return (
        ("list" in candidate or "types" in candidate or "category" in candidate)
        and "attack" in candidate
        and "cyber" in candidate
    )


def extract_first_url(text):
    candidate = text or ""
    matches = re.findall(r"https?://[^\s)>\"]+", candidate)
    for raw_url in matches:
        try:
            parsed = urllib.parse.urlparse(raw_url.strip())
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                return parsed.geturl()
        except RuntimeError:
            continue
    return None


def normalize_target_url(raw_url):
    candidate = (raw_url or "").strip()
    if not candidate:
        return None

    parsed = urllib.parse.urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    hostname = parsed.hostname
    if not hostname:
        return None

    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname) or ":" in hostname:
        validate_public_ip(hostname)
    else:
        validate_hostname(hostname)

    rebuilt = parsed._replace(netloc=parsed.netloc.lower())
    return urllib.parse.urlunparse(rebuilt)


def has_target_reference(text):
    candidate = normalize_security_query(text)
    if re.search(r"https?://[^\s)>\"]+", candidate):
        return True
    if re.search(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", candidate):
        return True
    return bool(search_company_directory(text, limit=1))


def extract_target_url(text):
    direct_url = extract_first_url(text)
    if direct_url:
        return normalize_target_url(direct_url)

    candidate = normalize_security_query(text)
    host_matches = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", candidate)
    for hostname in host_matches:
        try:
            return normalize_target_url(f"https://{hostname}")
        except RuntimeError:
            continue

    company_hits = search_company_directory(text, limit=1)
    if company_hits:
        try:
            return normalize_target_url(company_hits[0]["source_url"])
        except RuntimeError:
            return None
    return None


def detect_phishing_examples_request(text):
    candidate = normalize_security_query(text)
    wants_examples = any(token in candidate for token in ["example", "examples", "sample", "samples", "list"])
    wants_phishing = "phishing" in candidate or "spear phishing" in candidate
    explicit_count = re.search(r"\b\d{1,3}\b", candidate) is not None
    return wants_phishing and (wants_examples or explicit_count)


def detect_detection_rule_request(text):
    candidate = normalize_security_query(text)
    return "detect" in candidate and ("attack" in candidate or "phishing" in candidate or "ransomware" in candidate)


def detect_cve_search_request(text):
    candidate = normalize_security_query(text)
    return "cve-" in candidate or ("cve" in candidate and ("search" in candidate or "find" in candidate or "database" in candidate))


def detect_url_threat_request(text):
    candidate = normalize_security_query(text)
    return extract_target_url(text) is not None and any(
        token in candidate
        for token in ["analyze", "analysis", "audit", "review", "inspect", "threat", "url", "website", "site", "cyber"]
    )


def detect_url_report_request(text):
    candidate = normalize_security_query(text)
    return extract_target_url(text) is not None and "report" in candidate


def detect_openvas_scan_request(text):
    candidate = normalize_security_query(text)
    if not has_target_reference(text):
        return False
    return any(
        token in candidate
        for token in ["openvas", "open vas", "vulnerability scan", "vuln scan", "vulnerability assessment", "passive scan", "cyber analysis"]
    )


def detect_openvas_report_request(text):
    candidate = normalize_security_query(text)
    return detect_openvas_scan_request(text) and "report" in candidate


def should_default_to_site_analysis(text):
    candidate = normalize_security_query(text)
    if extract_target_url(text) is None:
        return False

    blocked_tokens = [
        "remember",
        "note",
        "phishing",
        "email",
        "log",
        "code",
        "sql",
        "xss",
        "csrf",
        "cve",
        "example",
        "examples",
        "dataset",
        "predict",
        "training",
        "learn",
    ]
    return not any(token in candidate for token in blocked_tokens)


def detect_learning_digest_request(text):
    candidate = normalize_security_query(text)
    phrases = [
        "learning digest",
        "latest digest",
        "three day digest",
        "3 day digest",
        "what did you learn",
        "latest trends",
        "recent learning",
    ]
    return any(phrase in candidate for phrase in phrases)


def detect_site_prediction_request(text):
    candidate = normalize_security_query(text)
    markers = ["predict", "dataset", "threat_score", "protection_score", "tls_days_remaining", "findings"]
    return sum(1 for marker in markers if marker in candidate) >= 2


def extract_prediction_arguments(text):
    candidate = text or ""

    def extract_number(name, default=0):
        match = re.search(rf"{name}\s*[:=]\s*(\d+)", candidate, re.IGNORECASE)
        return int(match.group(1)) if match else default

    findings_match = re.search(r"findings\s*[:=]\s*(.+)", candidate, re.IGNORECASE | re.DOTALL)
    findings = findings_match.group(1).strip() if findings_match else candidate

    return {
        "threat_score": extract_number("threat_score"),
        "protection_score": extract_number("protection_score"),
        "status": extract_number("status", 200),
        "tls_days_remaining": extract_number("tls_days_remaining"),
        "findings": findings,
    }


def detect_phishing_classification_request(text):
    candidate = normalize_security_query(text)
    explicit_analysis = ("phishing" in candidate or "email" in candidate) and (
        "classify" in candidate or "is this" in candidate or "analyze" in candidate
    )
    if explicit_analysis:
        return True

    email_markers = [
        "subject:",
        "dear user",
        "support team",
        "verify here",
        "update your kyc",
        "account requires",
        "click here",
    ]
    return sum(1 for marker in email_markers if marker in candidate) >= 2


def detect_log_analysis_request(text):
    candidate = (text or "").lower()
    return "log" in candidate and ("analyze" in candidate or "threat" in candidate or "rate" in candidate)


def detect_attack_label_request(text):
    candidate = (text or "").lower()
    return "what attack" in candidate or "attack type" in candidate or "classify attack" in candidate


def build_classifier_response(result):
    return "\n".join(
        [
            f"Model: {result['model']}",
            f"Predicted label: {result['label']}",
            f"Confidence: {result['confidence']}",
            "Top scores:",
            *[f"- {item['label']}: {item['score']}" for item in result["scores"]],
        ]
    )


def extract_phishing_red_flags(text):
    candidate = normalize_security_query(text)
    checks = [
        ("urgent or action-pressure wording", ["action required", "urgent", "without interruption", "final warning"]),
        ("generic greeting instead of your real name", ["dear user", "dear customer"]),
        ("asks you to verify account or KYC details", ["kyc", "verify", "update your details", "confirm your password"]),
        ("suspicious link that imitates a real brand", ["paytm-secure-verification", "login", ".co.in/login"]),
        ("brand impersonation or fake support signature", ["support team", "paytm support"]),
    ]
    hits = []
    for explanation, markers in checks:
        if any(marker in candidate for marker in markers):
            hits.append(explanation)
    return hits


def infer_phishing_label_from_flags(text):
    red_flags = extract_phishing_red_flags(text)
    if len(red_flags) >= 4:
        return {"label": "phishing", "confidence": 0.86, "red_flags": red_flags}
    if len(red_flags) >= 2:
        return {"label": "suspicious", "confidence": 0.74, "red_flags": red_flags}
    return None


def build_phishing_nlp_response(result, original_text):
    label = result["label"].replace("_", " ").title()
    confidence_pct = int(round(result["confidence"] * 100))
    red_flags = extract_phishing_red_flags(original_text)
    classification = "Phishing" if result["label"] == "phishing" else label
    lines = [
        f"Classification: {classification}",
        f"Confidence: {confidence_pct}%",
        "",
        "Easy explanation:",
    ]

    if result["label"] == "phishing":
        lines.append(
            "This message looks unsafe because it tries to make the user panic and click a suspicious verification link."
        )
    elif result["label"] == "suspicious":
        lines.append(
            "This message has some warning signs. It should be verified through the official app or website before acting."
        )
    else:
        lines.append(
            "This message does not strongly match the local phishing patterns, but you should still verify links and sender identity."
        )

    if red_flags:
        lines.extend(
            [
                "",
                "Main red flags:",
                *[f"- {flag}" for flag in red_flags[:5]],
            ]
        )

    lines.extend(
        [
            "",
            "What to do safely:",
            "- Do not open the link from the message.",
            "- Open the official Paytm app or official website directly instead.",
            "- Verify any KYC request inside the real account, not through the message link.",
            "- Report the message as phishing if it is not legitimate.",
        ]
    )
    return "\n".join(lines)


def build_conversation_export(conversation_id, export_format="markdown"):
    messages = get_conversation_messages(conversation_id)
    if not messages:
        raise RuntimeError("Conversation not found or has no messages.")

    if export_format == "json":
        payload = {
            "conversation_id": conversation_id,
            "exported_at": utc_now(),
            "messages": messages,
        }
        return json.dumps(payload, indent=2), "application/json", f"conversation-{conversation_id}.json"

    lines = [
        f"# DarkTraceX Conversation {conversation_id}",
        "",
        f"Exported at: {utc_now()}",
        "",
    ]
    for item in messages:
        lines.append(f"## {item['role'].title()} · {item['created_at']}")
        lines.append("")
        lines.append(item["text"])
        lines.append("")
        if item.get("meta", {}).get("tool_events"):
            lines.append("Tool events:")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(item["meta"]["tool_events"], indent=2))
            lines.append("```")
            lines.append("")

    return "\n".join(lines).strip() + "\n", "text/markdown; charset=utf-8", f"conversation-{conversation_id}.md"


def classify_with_threshold(model_name, text):
    result = classify_with_local_model(model_name, text)
    threshold = MODEL_THRESHOLDS.get(model_name, 0.7)
    result["threshold"] = threshold
    result["meets_threshold"] = result["confidence"] >= threshold
    return result


def detect_credential_theft_code(text):
    candidate = (text or "").lower()
    indicators = [
        "$_post",
        "captured_creds",
        "fwrite(",
        "passwd",
        "password",
        "location:",
        "header(",
    ]
    matches = sum(1 for item in indicators if item in candidate)
    if matches < 4:
        return None

    return {
        "classification": "Phishing / Credential Theft",
        "risk_level": "High",
        "analysis": (
            "This code is a credential-harvesting phishing handler. It accepts user-supplied login data, "
            "writes the captured credentials to a local file, and redirects the victim to the real site to hide the theft."
        ),
        "red_flags": [
            "Raw credential capture from POST parameters",
            "Credential storage in a hidden local file",
            "Post-capture redirect intended to hide malicious behavior",
            "No legitimate authentication or server-side validation flow",
        ],
        "defensive_guidance": [
            "Remove the script immediately from any server or repository",
            "Preserve forensic evidence and review access logs",
            "Rotate any exposed credentials and invalidate affected sessions",
            "Scan the host for related phishing artifacts and persistence",
            "Report the incident through the appropriate abuse, SOC, or incident-response channel",
        ],
    }


def build_credential_theft_response(result):
    lines = [
        "Classification: Phishing / Credential Theft",
        f"Threat Level: {result['risk_level']}",
        "",
        "What it is:",
        "This PHP snippet is a phishing credential harvester.",
        "",
        "How it works:",
        "It receives credentials from POST fields, stores them in a local file, and redirects the victim to the legitimate site to reduce suspicion.",
        "",
        "Why it is dangerous:",
        "It steals usernames and passwords, hides the theft with a redirect, and can directly support account compromise.",
        "",
        "Indicators:",
    ]
    lines.extend([f"- {item}" for item in result["red_flags"]])
    lines.extend(
        [
            "",
            "Defensive response:",
        ]
    )
    lines.extend([f"- {item}" for item in result["defensive_guidance"]])
    lines.extend(
        [
            "",
            "Safe replacement guidance:",
            "Use legitimate authentication handlers that validate input, avoid credential logging, and never redirect users as part of a deceptive flow.",
        ]
    )
    return "\n".join(lines)


def detect_sql_injection_code(text):
    candidate = (text or "").lower()
    indicators = [
        "select * from users where",
        "f\"select",
        "username = '{username}'",
        "password = '{password}'",
        "cur.execute(query)",
    ]
    matches = sum(1 for item in indicators if item in candidate)
    if matches < 3:
        return None

    return {
        "classification": "SQL Injection",
        "risk_level": "High",
        "secure_example": """import psycopg2

def secure_get_user(username, password):
    conn = psycopg2.connect("dbname=test user=app_user password=REPLACE_ME")
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM users WHERE username = %s AND password = %s;",
                (username, password),
            )
            return cur.fetchone()
    finally:
        conn.close()""",
    }


def build_sql_injection_response(result):
    lines = [
        "Classification: SQL Injection",
        f"Threat Level: {result['risk_level']}",
        "",
        "1. What it is:",
        "This code is vulnerable to SQL injection because untrusted input is inserted directly into the SQL statement.",
        "",
        "2. How it works:",
        "The query is built with string interpolation. An attacker can inject SQL syntax such as `admin' --` to alter the WHERE clause and bypass the password check.",
        "",
        "3. Why it is dangerous:",
        "It can allow authentication bypass, unauthorized data access, data modification, or broader database compromise depending on the database permissions.",
        "",
        "4. How to prevent it:",
        "- Use parameterized queries or prepared statements",
        "- Never concatenate user input into SQL strings",
        "- Remove hardcoded database credentials from source code",
        "- Apply least-privilege database permissions",
        "",
        "5. Secure code example:",
        result["secure_example"],
        "",
        "Extra finding:",
        "The connection string also contains a hardcoded password, which should be moved to environment variables or a secret manager.",
    ]
    return "\n".join(lines)


def build_site_analysis_error_reply(url, error_message):
    return "\n".join(
        [
            f"Cyber Analysis Report: {url}",
            "Status: Analysis unavailable",
            "",
            "Easy explanation:",
            "DarkTraceX could not complete the live website check from the current environment.",
            "",
            f"Reason: {error_message}",
            "",
            "What to do next:",
            "- Check internet and DNS access on this machine.",
            "- Try the request again after connectivity is available.",
            "- Or use a cached local report if you want an offline summary.",
        ]
    )


def load_learning_digest():
    if not LEARNING_DIGEST_PATH.exists():
        return None
    return LEARNING_DIGEST_PATH.read_text(encoding="utf-8").strip()


def list_learning_snapshots(limit=5):
    if not LEARNING_REPORTS_DIR.exists():
        return []

    snapshots = sorted(LEARNING_REPORTS_DIR.glob("learning-snapshot-*.json"), reverse=True)
    items = []
    for path in snapshots[:limit]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        items.append(
            {
                "file": path.name,
                "fetched_at": payload.get("fetched_at", ""),
                "items_collected": payload.get("items_collected", 0),
                "sources_checked": len(payload.get("sources", [])),
            }
        )
    return items


def conversation_stats():
    connection = db_connect()
    try:
        totals = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM conversations) AS conversations,
                (SELECT COUNT(*) FROM messages) AS messages,
                (SELECT COUNT(*) FROM notes) AS notes,
                (SELECT COUNT(*) FROM knowledge_docs) AS knowledge_docs
            """
        ).fetchone()
        recent_notes = connection.execute(
            """
            SELECT id, content, source, created_at
            FROM notes
            ORDER BY id DESC
            LIMIT 6
            """
        ).fetchall()
        latest_digest_updated_at = (
            datetime.fromtimestamp(LEARNING_DIGEST_PATH.stat().st_mtime, timezone.utc).isoformat()
            if LEARNING_DIGEST_PATH.exists()
            else None
        )
        return {
            "conversations": totals["conversations"],
            "messages": totals["messages"],
            "notes": totals["notes"],
            "knowledge_docs": totals["knowledge_docs"],
            "recent_notes": [dict(row) for row in recent_notes],
            "learning_snapshots": list_learning_snapshots(limit=3),
            "learning_digest_updated_at": latest_digest_updated_at,
        }
    finally:
        connection.close()


def validate_hostname(hostname):
    value = (hostname or "").strip().lower()
    if not value:
        raise RuntimeError("hostname is required.")
    if len(value) > 253 or not re.fullmatch(r"[a-z0-9.-]+", value):
        raise RuntimeError("Invalid hostname.")
    if value in {"localhost"} or value.endswith(".local"):
        raise RuntimeError("Local or private hostnames are not allowed.")
    return value


def validate_public_ip(ip_value):
    raw = (ip_value or "").strip()
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise RuntimeError("A valid IP address is required.") from exc

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise RuntimeError("Only public IP addresses are allowed.")

    return str(ip)


def ensure_public_hostname(hostname):
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise RuntimeError(f"Unable to resolve public hostname: {hostname}") from exc
    addresses = sorted({item[4][0] for item in infos})
    if not addresses:
        raise RuntimeError("No public address found for hostname.")

    for address in addresses:
        validate_public_ip(address)

    return addresses


def validate_url(url):
    raw = (url or "").strip()
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("A valid http or https URL is required.")
    hostname = parsed.hostname
    if not hostname:
        raise RuntimeError("A valid URL hostname is required.")

    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname) or ":" in hostname:
        validate_public_ip(hostname)
    else:
        validate_hostname(hostname)
        if not OFFLINE_MODE:
            ensure_public_hostname(hostname)

    return raw


def require_live_network(feature_name):
    if OFFLINE_MODE:
        raise RuntimeError(
            f"{feature_name} is disabled because DarkTraceX is running in offline-only mode. "
            "Use a cached local report or import local site evidence first."
        )


def safe_report_basename(url):
    parsed = urllib.parse.urlparse(url)
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", parsed.netloc + parsed.path).strip("-") or "url-report"


def parse_score_from_bar(bar_text):
    match = re.search(r"(\d{1,3})/100", bar_text or "")
    return int(match.group(1)) if match else 0


def load_cached_openvas_report(url):
    report_path = REPORTS_DIR / f"{safe_report_basename(url)}-cyber-analysis-report.md"
    if not report_path.exists():
        legacy_path = REPORTS_DIR / f"{safe_report_basename(url)}-openvas-local.md"
        report_path = legacy_path
    if not report_path.exists():
        return None

    content = report_path.read_text(encoding="utf-8")

    def extract(pattern, default=""):
        match = re.search(pattern, content, re.MULTILINE)
        return match.group(1).strip() if match else default

    def extract_graph_line(label):
        return extract(rf"- {re.escape(label)}: (.+)")

    findings = []
    findings_block = re.search(r"## Findings\s+(.*?)\s+## Offline CVE Hints", content, re.DOTALL)
    if findings_block:
        for line in findings_block.group(1).splitlines():
            line = line.strip()
            finding_match = re.match(r"- \[([A-Z]+)\] (.*?): (.*)", line)
            if finding_match:
                findings.append(
                    {
                        "severity": finding_match.group(1).lower(),
                        "title": finding_match.group(2),
                        "detail": finding_match.group(3),
                    }
                )

    cve_matches = []
    cve_block = re.search(r"## Offline CVE Hints\s+(.*?)\s+## Raw Summary", content, re.DOTALL)
    if cve_block:
        for line in cve_block.group(1).splitlines():
            line = line.strip()
            cve_match = re.match(r"- (CVE-[A-Z0-9-]+): (.*)", line)
            if cve_match:
                cve_matches.append({"doc_key": cve_match.group(1).lower(), "title": cve_match.group(2)})

    result = {
        "url": extract(r"- URL: (.+)"),
        "final_url": extract(r"- URL: (.+)"),
        "hostname": urllib.parse.urlparse(url).hostname or "",
        "status": int(extract(r"- HTTP status: (\d+)", "0") or 0),
        "severity": extract(r"- Severity: (.+)"),
        "scan_type": extract(r"- Scan type: (.+)", "cyber-analysis-report"),
        "threat_score": int(extract(r"- Threat score: (\d+)/100", "0") or 0),
        "protection_score": int(extract(r"- Protection score: (\d+)/100", "0") or 0),
        "graph": {
            "header_hardening": {
                "score": parse_score_from_bar(extract_graph_line("Header hardening")),
                "bar": extract_graph_line("Header hardening"),
            },
            "transport_security": {
                "score": parse_score_from_bar(extract_graph_line("Transport security")),
                "bar": extract_graph_line("Transport security"),
            },
            "tls_hygiene": {
                "score": parse_score_from_bar(extract_graph_line("TLS hygiene")),
                "bar": extract_graph_line("TLS hygiene"),
            },
            "disclosure_control": {
                "score": parse_score_from_bar(extract_graph_line("Disclosure control")),
                "bar": extract_graph_line("Disclosure control"),
            },
        },
        "findings": findings,
        "headers": {},
        "tls": None,
        "tls_days_remaining": None,
        "cve_matches": cve_matches,
        "summary": extract(r"## Raw Summary\s+(.*)", "").strip(),
        "report_path": str(report_path),
        "source_mode": "offline-cache",
    }
    return result


def load_cached_url_report(url):
    report_path = REPORTS_DIR / f"{safe_report_basename(url)}.md"
    if not report_path.exists():
        return None

    content = report_path.read_text(encoding="utf-8")

    def extract(pattern, default=""):
        match = re.search(pattern, content, re.MULTILINE)
        return match.group(1).strip() if match else default

    def extract_graph_line(label):
        return extract(rf"- {re.escape(label)}: (.+)")

    findings = []
    findings_block = re.search(r"## Findings\s+(.*?)\s+## Raw Summary", content, re.DOTALL)
    if findings_block:
        for line in findings_block.group(1).splitlines():
            line = line.strip()
            if line.startswith("- "):
                findings.append(line[2:])

    result = {
        "url": extract(r"- URL: (.+)"),
        "final_url": extract(r"- URL: (.+)"),
        "status": int(extract(r"- HTTP status: (\d+)", "0") or 0),
        "severity": extract(r"- Severity: (.+)"),
        "threat_score": int(extract(r"- Threat score: (\d+)/100", "0") or 0),
        "protection_score": int(extract(r"- Protection score: (\d+)/100", "0") or 0),
        "graph": {
            "header_hardening": {
                "score": parse_score_from_bar(extract_graph_line("Header hardening")),
                "bar": extract_graph_line("Header hardening"),
            },
            "transport_security": {
                "score": parse_score_from_bar(extract_graph_line("Transport security")),
                "bar": extract_graph_line("Transport security"),
            },
            "tls_hygiene": {
                "score": parse_score_from_bar(extract_graph_line("TLS hygiene")),
                "bar": extract_graph_line("TLS hygiene"),
            },
            "disclosure_control": {
                "score": parse_score_from_bar(extract_graph_line("Disclosure control")),
                "bar": extract_graph_line("Disclosure control"),
            },
        },
        "findings": findings,
        "headers": {},
        "tls_days_remaining": None,
        "cve_matches": [],
        "summary": extract(r"## Raw Summary\s+(.*)", "").strip(),
        "report_path": str(report_path),
        "source_mode": "offline-cache",
    }
    return result


def tool_dns_lookup(arguments):
    require_live_network("dns_lookup")
    hostname = validate_hostname(arguments.get("hostname"))
    addresses = ensure_public_hostname(hostname)
    return {"hostname": hostname, "addresses": addresses}


def tool_reverse_dns(arguments):
    require_live_network("reverse_dns")
    ip_value = validate_public_ip(arguments.get("ip"))
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip_value)
    except socket.herror as exc:
        raise RuntimeError(f"No reverse DNS entry for {ip_value}.") from exc

    return {
        "ip": ip_value,
        "hostname": hostname,
        "aliases": aliases,
    }


def fetch_url(url, method="HEAD"):
    req = request.Request(
        url,
        headers={"User-Agent": "Blackwall/1.0"},
        method=method,
    )
    return request.urlopen(req, timeout=15, context=SSL_CONTEXT)


def tool_http_headers(arguments):
    require_live_network("http_headers")
    url = validate_url(arguments.get("url"))
    try:
        response = fetch_url(url, method="HEAD")
    except error.HTTPError as exc:
        if exc.code != 405:
            raise
        response = fetch_url(url, method="GET")

    with response:
        headers = dict(response.headers.items())
        set_cookie_headers = response.headers.get_all("Set-Cookie") or []
        return {
            "url": url,
            "final_url": response.geturl(),
            "status": response.status,
            "headers": headers,
            "set_cookie_headers": set_cookie_headers,
        }


def tool_security_headers_audit(arguments):
    require_live_network("security_headers_audit")
    header_result = tool_http_headers(arguments)
    headers = {key.lower(): value for key, value in header_result["headers"].items()}

    recommended = {
        "strict-transport-security": "Missing HSTS header.",
        "content-security-policy": "Missing Content-Security-Policy header.",
        "x-content-type-options": "Missing X-Content-Type-Options header.",
        "referrer-policy": "Missing Referrer-Policy header.",
    }

    findings = []
    for header_name, missing_message in recommended.items():
        value = headers.get(header_name)
        if header_name == "content-security-policy":
            if not value and not headers.get("content-security-policy-report-only"):
                findings.append(missing_message)
            elif not value and headers.get("content-security-policy-report-only"):
                findings.append("Only Content-Security-Policy-Report-Only was observed.")
            continue
        if not value:
            findings.append(missing_message)

    if headers.get("x-frame-options") is None and headers.get("content-security-policy") is None:
        findings.append("Neither X-Frame-Options nor CSP frame-ancestors is present.")

    if headers.get("server") and headers.get("server").strip().lower() not in {"server", "unknown"}:
        findings.append(f"Server header exposed: {headers['server']}")

    if not findings:
        findings.append("No obvious missing baseline headers were detected.")

    return {
        "url": header_result["url"],
        "status": header_result["status"],
        "final_url": header_result["final_url"],
        "findings": findings,
        "headers": header_result["headers"],
        "set_cookie_headers": header_result.get("set_cookie_headers", []),
    }


def tool_tls_inspect(arguments):
    require_live_network("tls_inspect")
    hostname = validate_hostname(arguments.get("hostname"))
    ensure_public_hostname(hostname)
    port = int(arguments.get("port", 443))
    if port < 1 or port > 65535:
        raise RuntimeError("Invalid port.")

    context = SSL_CONTEXT or ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            cert = secure_sock.getpeercert()

    subject = dict(item[0] for item in cert.get("subject", []))
    issuer = dict(item[0] for item in cert.get("issuer", []))

    return {
        "hostname": hostname,
        "port": port,
        "subject_common_name": subject.get("commonName"),
        "issuer_common_name": issuer.get("commonName"),
        "serial_number": cert.get("serialNumber"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_names": [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"],
    }


def analyze_header_exposures(header_result):
    headers = {key.lower(): value for key, value in header_result["headers"].items()}
    findings = []
    cookies = list(header_result.get("set_cookie_headers") or [])
    if not cookies:
        raw_cookies = header_result["headers"].get("Set-Cookie") or headers.get("set-cookie") or ""
        if raw_cookies:
            cookies = [item.strip() for item in re.split(r",(?=[A-Za-z0-9!#$%&'*+.^_`|~-]+=)", raw_cookies) if item.strip()]

    server_value = (headers.get("server") or "").strip()
    if server_value and server_value.lower() not in {"server", "unknown"}:
        findings.append({"severity": "medium", "title": "Server Fingerprint Exposed", "detail": f"Server header is exposed as `{headers['server']}`."})
    if headers.get("x-powered-by"):
        findings.append({"severity": "medium", "title": "Technology Banner Exposed", "detail": f"`X-Powered-By` reveals `{headers['x-powered-by']}`."})
    if headers.get("access-control-allow-origin") == "*":
        findings.append({"severity": "medium", "title": "Wildcard CORS Policy", "detail": "The response allows `Access-Control-Allow-Origin: *`, which may be overly broad."})
    if "strict-transport-security" not in headers and header_result["final_url"].startswith("https://"):
        findings.append({"severity": "medium", "title": "Missing HSTS", "detail": "HTTPS is used, but HSTS was not observed."})
    if "content-security-policy" not in headers and "content-security-policy-report-only" not in headers:
        findings.append({"severity": "medium", "title": "Missing CSP", "detail": "No Content-Security-Policy header was observed."})
    elif "content-security-policy" not in headers and "content-security-policy-report-only" in headers:
        findings.append({"severity": "low", "title": "CSP Is Report-Only", "detail": "A report-only CSP was observed, but no enforcing Content-Security-Policy header was present."})
    if "x-content-type-options" not in headers:
        findings.append({"severity": "low", "title": "Missing MIME-Sniffing Protection", "detail": "No X-Content-Type-Options header was observed."})
    if "referrer-policy" not in headers:
        findings.append({"severity": "low", "title": "Missing Referrer Policy", "detail": "No Referrer-Policy header was observed."})
    if headers.get("x-frame-options") is None and "content-security-policy" not in headers:
        findings.append({"severity": "medium", "title": "Weak Clickjacking Protection", "detail": "Neither X-Frame-Options nor CSP frame controls were observed."})
    if 300 <= header_result["status"] < 400:
        findings.append({"severity": "low", "title": "Redirect Observed", "detail": f"The URL returned HTTP {header_result['status']} before final resolution."})

    if cookies:
        insecure_cookie_count = 0
        weak_samesite_count = 0
        for cookie in cookies:
            lowered = cookie.lower()
            if "secure" not in lowered or "httponly" not in lowered:
                insecure_cookie_count += 1
            if "samesite=" not in lowered:
                weak_samesite_count += 1
        if insecure_cookie_count:
            findings.append(
                {
                    "severity": "medium",
                    "title": "Cookie Flags Need Review",
                    "detail": f"{insecure_cookie_count} observed cookie definitions lacked Secure or HttpOnly markers in the visible response headers.",
                }
            )
        if weak_samesite_count:
            findings.append(
                {
                    "severity": "low",
                    "title": "Cookie SameSite Not Visible",
                    "detail": f"{weak_samesite_count} observed cookie definitions did not visibly include SameSite.",
                }
            )

    return findings


def infer_cve_queries_from_headers(hostname, header_result):
    headers = {key.lower(): value for key, value in header_result["headers"].items()}
    queries = []
    blocked = {
        "server",
        "unknown",
        "cloudfront",
        "cloudflare",
        "gws",
        "envoy",
        "openresty",
        "apache",
        "nginx",
        "iis",
        "akamai",
    }
    if hostname:
        queries.append(hostname.split(".")[0])
    for header_name in ["server", "x-powered-by"]:
        value = headers.get(header_name)
        if not value:
            continue
        token_match = re.match(r"([a-zA-Z0-9._+-]+)", value)
        if token_match:
            token = token_match.group(1).lower()
            if token not in blocked and len(token) >= 4:
                queries.append(token)
    return [item for item in queries if item]


def score_openvas_scan(url, header_audit, tls_result=None):
    header_result = {
        "url": header_audit["url"],
        "final_url": header_audit["final_url"],
        "status": header_audit["status"],
        "headers": header_audit["headers"],
    }
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    dimensions, days_left = compute_threat_dimensions(url, header_audit, tls_result)
    findings = analyze_header_exposures(header_result)

    if not url.startswith("https://"):
        findings.append({"severity": "high", "title": "No HTTPS", "detail": "The target URL does not use HTTPS, which weakens transport protection."})
    if tls_result and days_left is not None and days_left <= 30:
        findings.append({"severity": "medium", "title": "Certificate Expiry Window", "detail": f"The observed TLS certificate expires in {days_left} days."})

    severity_weights = {"critical": 35, "high": 24, "medium": 12, "low": 6}
    weighted_risk = sum(severity_weights.get(item["severity"], 0) for item in findings)
    passive_exposure_score = min(100, weighted_risk)
    base_threat = max(0, 100 - round(sum(dimensions.values()) / len(dimensions)))
    threat_score = min(100, round((base_threat * 0.55) + (passive_exposure_score * 0.45)))
    protection_score = max(0, 100 - threat_score)

    if threat_score >= 75:
        severity = "Critical"
    elif threat_score >= 55:
        severity = "High"
    elif threat_score >= 30:
        severity = "Medium"
    else:
        severity = "Low"

    cve_queries = infer_cve_queries_from_headers(hostname, header_result)
    cve_matches = []
    for query in cve_queries:
        for item in search_cve_database(query, limit=3):
            if item["doc_key"] not in {match["doc_key"] for match in cve_matches}:
                cve_matches.append(item)
        if len(cve_matches) >= 5:
            break

    return {
        "url": url,
        "final_url": header_audit["final_url"],
        "hostname": hostname,
        "status": header_audit["status"],
        "severity": severity,
        "scan_type": "openvas-local-passive",
        "threat_score": threat_score,
        "protection_score": protection_score,
        "graph": {key: {"score": value, "bar": build_score_bar(value)} for key, value in dimensions.items()},
        "findings": findings,
        "headers": header_audit["headers"],
        "tls": tls_result,
        "tls_days_remaining": days_left,
        "cve_matches": cve_matches[:5],
    }


def build_openvas_local_response(result):
    lines = [
        f"Cyber Analysis Report: {result['final_url']}",
        f"Severity: {result['severity']}",
        f"Threat score: {result['threat_score']}/100",
        f"Protection score: {result['protection_score']}/100",
        "",
        "Easy summary:",
        (
            "This passive scan found only limited visible exposure on the public website surface."
            if result["severity"] == "Low"
            else "This passive scan found visible web-security gaps that deserve review."
        ),
        "",
        "Threat graph:",
        f"- Website protection   {result['graph']['header_hardening']['bar']}",
        f"- Connection safety    {result['graph']['transport_security']['bar']}",
        f"- Certificate health   {result['graph']['tls_hygiene']['bar']}",
        f"- Privacy exposure     {result['graph']['disclosure_control']['bar']}",
        "",
        "Key findings:",
    ]
    if result["findings"]:
        lines.extend([f"- [{item['severity'].upper()}] {item['title']}: {item['detail']}" for item in result["findings"][:10]])
    else:
        lines.append("- No obvious passive exposure findings were detected in the observed response.")

    if result["tls_days_remaining"] is not None:
        lines.extend(["", f"TLS days remaining: {result['tls_days_remaining']}"])

    if result.get("learned_assessment"):
        learned = result["learned_assessment"]
        lines.extend(
            [
                "",
                "Learned assessment:",
                f"- Model label: {learned['label'].title()}",
                f"- Confidence: {int(round(learned['confidence'] * 100))}%",
                f"- Models used: {', '.join(learned.get('models_used', []))}",
            ]
        )

    lines.extend(["", "CVE bug context:"])
    lines.extend(build_cve_bug_context_lines(result["cve_matches"], limit=3))

    lines.extend(
        [
            "",
            "Limit:",
            "- This is a passive local assessment, not an intrusive vulnerability exploit scan.",
        ]
    )
    return "\n".join(lines)


def build_score_bar(score):
    filled = max(0, min(10, int(round(score / 10))))
    return "[" + ("#" * filled) + ("-" * (10 - filled)) + f"] {score}/100"


def compute_threat_dimensions(url, header_audit, tls_result=None):
    findings = header_audit["findings"]
    header_hardening = 100
    transport_security = 100 if url.startswith("https://") else 35
    disclosure = 100
    tls_hygiene = 100 if tls_result else (35 if url.startswith("https://") else 0)

    for finding in findings:
        if "HSTS" in finding:
            header_hardening -= 25
        elif "Content-Security-Policy" in finding:
            header_hardening -= 20
        elif "X-Content-Type-Options" in finding:
            header_hardening -= 10
        elif "Referrer-Policy" in finding:
            header_hardening -= 10
        elif "X-Frame-Options" in finding or "frame-ancestors" in finding:
            header_hardening -= 15
        elif "Server header exposed" in finding:
            disclosure -= 18

    days_left = None
    if tls_result and tls_result.get("not_after"):
        expiry_date = datetime.strptime(tls_result["not_after"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = max(0, int((expiry_date - datetime.now(timezone.utc)).total_seconds() // 86400))
        tls_hygiene = 90 if days_left > 90 else 75 if days_left > 30 else 45

    dimensions = {
        "header_hardening": max(0, min(100, header_hardening)),
        "transport_security": max(0, min(100, transport_security)),
        "tls_hygiene": max(0, min(100, tls_hygiene)),
        "disclosure_control": max(0, min(100, disclosure)),
    }
    return dimensions, days_left


def score_url_threat(url, header_audit, tls_result=None):
    dimensions, days_left = compute_threat_dimensions(url, header_audit, tls_result)
    protection_score = round(sum(dimensions.values()) / len(dimensions))
    threat_score = max(0, 100 - protection_score)
    if threat_score >= 75:
        severity = "Critical"
    elif threat_score >= 55:
        severity = "High"
    elif threat_score >= 30:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "url": url,
        "final_url": header_audit["final_url"],
        "status": header_audit["status"],
        "severity": severity,
        "threat_score": threat_score,
        "protection_score": protection_score,
        "graph": {key: {"score": value, "bar": build_score_bar(value)} for key, value in dimensions.items()},
        "findings": header_audit["findings"],
        "headers": header_audit["headers"],
        "tls_days_remaining": days_left,
    }


def build_url_threat_response(result):
    cve_lines = ["CVE bug context:", *build_cve_bug_context_lines(result.get("cve_matches", []), limit=3)]

    lines = [
        f"URL Threat Report: {result['final_url']}",
        f"Severity: {result['severity']}",
        f"Threat score: {result['threat_score']}/100",
        f"Protection score: {result['protection_score']}/100",
        "",
        "Easy summary:",
        (
            "This site currently shows a low level of visible web-exposure risk in the local checks."
            if result["severity"] == "Low"
            else "This site shows some visible web-security gaps in the local checks and should be reviewed."
        ),
        "",
        "Threat graph:",
        f"- Website protection   {result['graph']['header_hardening']['bar']}",
        f"- Connection safety    {result['graph']['transport_security']['bar']}",
        f"- Certificate health   {result['graph']['tls_hygiene']['bar']}",
        f"- Privacy exposure     {result['graph']['disclosure_control']['bar']}",
        "",
        "Main findings:",
        *[f"- {item}" for item in result["findings"][:8]],
    ]
    if result["tls_days_remaining"] is not None:
        lines.extend(["", f"TLS days remaining: {result['tls_days_remaining']}"])
    if result.get("learned_assessment"):
        learned = result["learned_assessment"]
        lines.extend(
            [
                "",
                "Learned assessment:",
                f"- Model label: {learned['label'].title()}",
                f"- Confidence: {int(round(learned['confidence'] * 100))}%",
            ]
        )
    lines.extend(["", *cve_lines])
    return "\n".join(lines)


def tool_url_threat_report(arguments):
    url = validate_url(arguments.get("url"))
    if OFFLINE_MODE:
        cached = load_cached_url_report(url)
        if not cached:
            raise RuntimeError(
                "Offline-only mode is enabled. No cached URL threat report was found for this target."
            )
        return cached
    parsed = urllib.parse.urlparse(url)
    header_audit = tool_security_headers_audit({"url": url})
    tls_result = None
    if parsed.scheme == "https":
        tls_result = tool_tls_inspect({"hostname": parsed.hostname, "port": parsed.port or 443})
    result = score_url_threat(url, header_audit, tls_result)
    hostname = (parsed.hostname or "").lower()
    cve_matches = []
    if hostname:
        cve_matches = search_cve_database(hostname.split(".")[0], limit=3)
    row_like = {
        "threat_score": result["threat_score"],
        "protection_score": result["protection_score"],
        "status": result["status"],
        "tls_days_remaining": result["tls_days_remaining"] if result["tls_days_remaining"] is not None else 0,
        "findings": " | ".join(result["findings"]),
    }
    learned_assessment = None
    try:
        learned_assessment = ensemble_site_exposure_predictions(extract_site_features_from_row(row_like))
    except RuntimeError:
        learned_assessment = None
    result["tls"] = tls_result
    result["cve_matches"] = cve_matches
    result["learned_assessment"] = learned_assessment
    result["summary"] = build_url_threat_response(result)
    return result


def tool_openvas_local_scan(arguments):
    url = validate_url(arguments.get("url"))
    if OFFLINE_MODE:
        cached = load_cached_openvas_report(url)
        if not cached:
            raise RuntimeError(
                "Offline-only mode is enabled. No cached cyber analysis report was found for this target."
            )
        return cached
    parsed = urllib.parse.urlparse(url)
    header_audit = tool_security_headers_audit({"url": url})
    tls_result = None
    if parsed.scheme == "https":
        tls_result = tool_tls_inspect({"hostname": parsed.hostname, "port": parsed.port or 443})
    result = score_openvas_scan(url, header_audit, tls_result)
    row_like = {
        "threat_score": result["threat_score"],
        "protection_score": result["protection_score"],
        "status": result["status"],
        "tls_days_remaining": result["tls_days_remaining"] if result["tls_days_remaining"] is not None else 0,
        "findings": " | ".join(item["title"] for item in result["findings"]),
    }
    learned_assessment = None
    try:
        learned_assessment = ensemble_site_exposure_predictions(extract_site_features_from_row(row_like))
    except RuntimeError:
        learned_assessment = None
    result["learned_assessment"] = learned_assessment
    result["summary"] = build_openvas_local_response(result)
    return result


def tool_create_url_report_file(arguments):
    if OFFLINE_MODE:
        url = validate_url(arguments.get("url"))
        cached = load_cached_url_report(url)
        if not cached:
            raise RuntimeError(
                "Offline-only mode is enabled. Create the report from local evidence or use an existing cached report."
            )
        return {
            "report_path": cached["report_path"],
            "url": cached["final_url"],
            "severity": cached["severity"],
            "threat_score": cached["threat_score"],
            "graph": cached["graph"],
        }
    result = tool_url_threat_report(arguments)
    REPORTS_DIR.mkdir(exist_ok=True)
    parsed = urllib.parse.urlparse(result["final_url"])
    safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "-", parsed.netloc + parsed.path).strip("-") or "url-report"
    report_path = REPORTS_DIR / f"{safe_name}.md"
    report_body = "\n".join(
        [
            "# URL Threat Report",
            "",
            f"- URL: {result['final_url']}",
            f"- Severity: {result['severity']}",
            f"- Threat score: {result['threat_score']}/100",
            f"- Protection score: {result['protection_score']}/100",
            f"- HTTP status: {result['status']}",
            "",
            "## Threat Graph",
            "",
            f"- Website protection: {result['graph']['header_hardening']['bar']}",
            f"- Connection safety: {result['graph']['transport_security']['bar']}",
            f"- Certificate health: {result['graph']['tls_hygiene']['bar']}",
            f"- Privacy exposure: {result['graph']['disclosure_control']['bar']}",
            "",
            "## Findings",
            "",
            *[f"- {item}" for item in result["findings"]],
            "",
            "## Raw Summary",
            "",
            result["summary"],
            "",
        ]
    )
    report_path.write_text(report_body, encoding="utf-8")
    return {
        "report_path": str(report_path),
        "url": result["final_url"],
        "severity": result["severity"],
        "threat_score": result["threat_score"],
        "graph": result["graph"],
    }


def tool_create_openvas_report_file(arguments):
    if OFFLINE_MODE:
        url = validate_url(arguments.get("url"))
        cached = load_cached_openvas_report(url)
        if not cached:
            raise RuntimeError(
                "Offline-only mode is enabled. Create the cyber analysis report from local evidence or use an existing cached report."
            )
        return {
            "report_path": cached["report_path"],
            "url": cached["final_url"],
            "severity": cached["severity"],
            "threat_score": cached["threat_score"],
            "protection_score": cached["protection_score"],
            "graph": cached["graph"],
            "scan_type": cached["scan_type"],
        }
    result = tool_openvas_local_scan(arguments)
    REPORTS_DIR.mkdir(exist_ok=True)
    parsed = urllib.parse.urlparse(result["final_url"])
    safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "-", parsed.netloc + parsed.path).strip("-") or "cyber-analysis-report"
    report_path = REPORTS_DIR / f"{safe_name}-cyber-analysis-report.md"
    report_body = "\n".join(
        [
            "# Cyber Analysis Report",
            "",
            f"- URL: {result['final_url']}",
            f"- Scan type: {result['scan_type']}",
            f"- Severity: {result['severity']}",
            f"- Threat score: {result['threat_score']}/100",
            f"- Protection score: {result['protection_score']}/100",
            f"- HTTP status: {result['status']}",
            "",
            "## Threat Graph",
            "",
            f"- Website protection: {result['graph']['header_hardening']['bar']}",
            f"- Connection safety: {result['graph']['transport_security']['bar']}",
            f"- Certificate health: {result['graph']['tls_hygiene']['bar']}",
            f"- Privacy exposure: {result['graph']['disclosure_control']['bar']}",
            "",
            "## Findings",
            "",
            *[f"- [{item['severity'].upper()}] {item['title']}: {item['detail']}" for item in result["findings"]],
            "",
            "## Offline CVE Hints",
            "",
            *([f"- {item['doc_key'].upper()}: {item['title']}" for item in result["cve_matches"]] or ["- None found from visible fingerprints."]),
            "",
            "## Raw Summary",
            "",
            result["summary"],
            "",
        ]
    )
    report_path.write_text(report_body, encoding="utf-8")
    return {
        "report_path": str(report_path),
        "url": result["final_url"],
        "severity": result["severity"],
        "threat_score": result["threat_score"],
        "protection_score": result["protection_score"],
        "graph": result["graph"],
        "scan_type": result["scan_type"],
    }


def tool_remember_note(arguments):
    return remember_note(arguments.get("content"), source="tool")


def tool_search_notes(arguments):
    return {"results": search_notes(arguments.get("query"))}


def tool_search_knowledge(arguments):
    return {"results": search_knowledge(arguments.get("query"))}


def tool_search_rag_context(arguments):
    limit = int(arguments.get("limit", 6))
    limit = max(1, min(limit, 10))
    rag_bundle = build_rag_bundle(arguments.get("query"), limit=limit)
    return rag_bundle


def tool_search_code_examples(arguments):
    return {"results": search_code_examples(arguments.get("query"))}


def tool_search_detection_rules(arguments):
    return {"results": search_detection_rules(arguments.get("query"))}


def tool_search_cve_database(arguments):
    limit = int(arguments.get("limit", 5))
    limit = max(1, min(limit, 10))
    return {"results": search_cve_database(arguments.get("query"), limit=limit)}


def tool_search_phishing_examples(arguments):
    limit = int(arguments.get("limit", 100))
    limit = max(1, min(limit, 100))
    return {"results": search_phishing_examples(arguments.get("query"), limit=limit)}


def tool_predict_site_exposure(arguments):
    row_like = {
        "threat_score": arguments.get("threat_score", 0),
        "protection_score": arguments.get("protection_score", 0),
        "status": arguments.get("status", 0),
        "tls_days_remaining": arguments.get("tls_days_remaining", 0),
        "findings": arguments.get("findings", ""),
    }
    feature_map = extract_site_features_from_row(row_like)
    prediction = ensemble_site_exposure_predictions(feature_map)
    prediction["features"] = feature_map
    return prediction


def build_site_prediction_response(result):
    lines = [
        f"Predicted exposure level: {result['label'].title()}",
        f"Confidence: {int(round(result['confidence'] * 100))}%",
        f"Models used: {', '.join(result.get('models_used', [])) or 'unknown'}",
        "",
        "Probability view:",
    ]
    lines.extend([f"- {item['label'].title()}: {int(round(item['score'] * 100))}%" for item in result["scores"]])
    lines.extend(
        [
            "",
            "Feature summary used:",
            f"- Threat score feature: {round(result['features']['threat_score'] * 100)}",
            f"- Protection score feature: {round(result['features']['protection_score'] * 100)}",
            f"- Status ok: {'yes' if result['features']['status_ok'] else 'no'}",
            f"- Missing HSTS: {'yes' if result['features']['missing_hsts'] else 'no'}",
            f"- Missing CSP: {'yes' if result['features']['missing_csp'] else 'no'}",
            f"- Server header exposed: {'yes' if result['features']['server_header_exposed'] else 'no'}",
        ]
    )
    return "\n".join(lines)


def tool_classify_defense_text(arguments):
    model_name = (arguments.get("model") or "").strip()
    text = arguments.get("text") or ""
    return classify_with_local_model(model_name, text)


TOOLS = {
    "remember_note": tool_remember_note,
    "search_notes": tool_search_notes,
    "search_knowledge": tool_search_knowledge,
    "search_rag_context": tool_search_rag_context,
    "search_code_examples": tool_search_code_examples,
    "search_detection_rules": tool_search_detection_rules,
    "search_cve_database": tool_search_cve_database,
    "search_phishing_examples": tool_search_phishing_examples,
    "predict_site_exposure": tool_predict_site_exposure,
    "classify_defense_text": tool_classify_defense_text,
    "dns_lookup": tool_dns_lookup,
    "reverse_dns": tool_reverse_dns,
    "http_headers": tool_http_headers,
    "security_headers_audit": tool_security_headers_audit,
    "tls_inspect": tool_tls_inspect,
    "url_threat_report": tool_url_threat_report,
    "create_url_report_file": tool_create_url_report_file,
    "openvas_local_scan": tool_openvas_local_scan,
    "create_openvas_report_file": tool_create_openvas_report_file,
}


def build_gemini_contents(messages):
    contents = []
    for message in messages[-MAX_CONTEXT_MESSAGES:]:
        role = message.get("role")
        text = (message.get("text") or "").strip()
        if role not in {"user", "assistant"} or not text:
            continue
        contents.append(
            {
                "role": "model" if role == "assistant" else "user",
                "parts": [{"text": text}],
            }
        )
    return contents


def extract_gemini_text(data):
    for candidate in data.get("candidates", []):
        content = candidate.get("content", {})
        for part in content.get("parts", []):
            text = (part.get("text") or "").strip()
            if text:
                return text

    prompt_feedback = data.get("promptFeedback", {})
    block_reason = prompt_feedback.get("blockReason")
    if block_reason:
        raise RuntimeError(f"Gemini blocked the prompt: {block_reason}")

    raise RuntimeError("The model returned no text.")


def call_gemini(contents):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set.")

    payload = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": contents,
        "generationConfig": {"temperature": 0.5},
    }

    url = f"{GEMINI_API_URL}/{DEFAULT_MODEL}:generateContent"
    req = request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-goog-api-key": api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=90, context=SSL_CONTEXT) as response:
            body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
            message = parsed.get("error", {}).get("message") or raw
        except json.JSONDecodeError:
            message = raw
        raise RuntimeError(f"Gemini API error ({exc.code}): {message}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc

    return extract_gemini_text(json.loads(body))


def build_local_prompt(messages, memory_hits, knowledge_hits, tool_events, rag_bundle):
    sections = [SYSTEM_PROMPT]

    if rag_bundle and rag_bundle.get("hits"):
        sections.append(format_rag_context(rag_bundle))
    elif knowledge_hits:
        sections.append("Offline knowledge base matches:\n" + json.dumps(knowledge_hits, indent=2))
    if memory_hits and not (rag_bundle and rag_bundle.get("hits")):
        sections.append("Relevant memory:\n" + json.dumps(memory_hits, indent=2))
    if tool_events:
        sections.append("Executed tool results:\n" + json.dumps(tool_events, indent=2))

    transcript = []
    for message in messages[-MAX_CONTEXT_MESSAGES:]:
        role = message.get("role")
        text = (message.get("text") or "").strip()
        if role in {"user", "assistant"} and text:
            transcript.append(f"{role.upper()}: {text}")

    sections.append("Conversation:\n" + "\n".join(transcript))
    sections.append(
        "Respond to the latest user message. Do not expose internal tool syntax in a normal answer. "
        "If a tool is needed, return JSON only using the declared tool protocol."
    )
    return "\n\n".join(sections)


def choose_ollama_model(messages):
    last_user_text = next(
        (message.get("text", "") for message in reversed(messages) if message.get("role") == "user"),
        "",
    ).lower()

    if any(token in last_user_text for token in ["code", "sql", "xss", "csrf", "secure fix", "snippet"]):
        return OLLAMA_CODE_MODEL
    if any(
        token in last_user_text
        for token in ["analyze", "analysis", "report", "threat", "log", "email", "phishing", "website", "url"]
    ):
        return OLLAMA_ANALYSIS_MODEL
    return OLLAMA_GENERAL_MODEL


def call_ollama(prompt, model_name):
    payload = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.4},
    }

    req = request.Request(
        OLLAMA_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=120) as response:
            body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Ollama API error ({exc.code}): {raw}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Ollama is unavailable: {exc.reason}") from exc

    data = json.loads(body)
    text = (data.get("response") or "").strip()
    if not text:
        raise RuntimeError("The local model returned no text.")
    return text


def build_gemini_context_messages(memory_hits, knowledge_hits, tool_events):
    parts = []
    rag_bundle = build_rag_bundle("", memory_hits=memory_hits, knowledge_hits=knowledge_hits)
    if rag_bundle.get("hits"):
        parts.append(format_rag_context(rag_bundle))
    elif knowledge_hits:
        parts.append("Offline knowledge base matches:\n" + json.dumps(knowledge_hits, indent=2))
    if memory_hits and not rag_bundle.get("hits"):
        parts.append("Relevant memory:\n" + json.dumps(memory_hits, indent=2))
    if tool_events:
        parts.append("Executed tool results:\n" + json.dumps(tool_events, indent=2))
    if not parts:
        return []
    return [{"role": "user", "parts": [{"text": "\n\n".join(parts)}]}]


def build_offline_fallback(last_user_text, knowledge_hits, memory_hits, rag_bundle=None):
    lines = [
        "Local model is unavailable, so this response is coming from local RAG retrieval over stored notes and knowledge.",
    ]
    if rag_bundle and rag_bundle.get("hits"):
        lines.append("RAG matches:")
        for item in rag_bundle["hits"][:4]:
            lines.append(f"- {item['title']} ({item['source_type']}): {item['snippet']}")
    elif knowledge_hits:
        lines.append("Knowledge base matches:")
        for hit in knowledge_hits[:3]:
            lines.append(f"- {hit['title']}: {hit['content'][:280]}")
    if memory_hits and not (rag_bundle and rag_bundle.get("hits")):
        lines.append("Related memory:")
        for hit in memory_hits[:3]:
            lines.append(f"- {hit['content']}")
    if not knowledge_hits and not memory_hits:
        lines.append(f"No offline knowledge match was found for: {last_user_text}")
    return "\n".join(lines)


def call_model(messages, memory_hits, knowledge_hits, tool_events, rag_bundle):
    if MODEL_PROVIDER == "ollama":
        prompt = build_local_prompt(messages, memory_hits, knowledge_hits, tool_events, rag_bundle)
        model_name = choose_ollama_model(messages)
        return call_ollama(prompt, model_name), model_name

    if MODEL_PROVIDER == "gemini":
        if OFFLINE_MODE:
            raise RuntimeError("Gemini is disabled in offline-only mode. Use the local model or offline knowledge paths.")
        contents = build_gemini_contents(messages) + build_gemini_context_messages(
            memory_hits, knowledge_hits, tool_events
        )
        return call_gemini(contents), DEFAULT_MODEL

    raise RuntimeError(f"Unsupported MODEL_PROVIDER: {MODEL_PROVIDER}")


def parse_tool_call(text):
    candidate = (text or "").strip()
    if not candidate.startswith("{"):
        return None
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    tool_name = parsed.get("tool_name")
    arguments = parsed.get("arguments", {})
    if tool_name in TOOLS and isinstance(arguments, dict):
        return {"tool_name": tool_name, "arguments": arguments}
    return None


def extract_embedded_tool_call(text):
    candidate = (text or "").strip()
    if "\"tool_name\"" not in candidate or "\"arguments\"" not in candidate:
        return None

    start_indexes = [index for index, char in enumerate(candidate) if char == "{"]
    end_indexes = [index for index, char in enumerate(candidate) if char == "}"]
    for start in start_indexes:
        for end in reversed(end_indexes):
            if end <= start:
                continue
            snippet = candidate[start : end + 1]
            tool_call = parse_tool_call(snippet)
            if tool_call:
                return tool_call
    return None


def run_tool(tool_name, arguments):
    tool = TOOLS[tool_name]
    result = tool(arguments)
    return {
        "tool_name": tool_name,
        "arguments": arguments,
        "result": result,
    }


def handle_chat(messages):
    working_messages = [dict(message) for message in messages]
    last_user_text = next(
        (message.get("text", "") for message in reversed(working_messages) if message.get("role") == "user"),
        "",
    )
    credential_theft_result = detect_credential_theft_code(last_user_text)
    if credential_theft_result:
        return {
            "reply": build_credential_theft_response(credential_theft_result),
            "tool_events": [],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "rule-based-defense",
        }

    sql_injection_result = detect_sql_injection_code(last_user_text)
    if sql_injection_result:
        return {
            "reply": build_sql_injection_response(sql_injection_result),
            "tool_events": [],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "rule-based-defense",
        }

    if detect_code_example_request(last_user_text):
        code_results = search_code_examples(last_user_text, limit=3)
        return {
            "reply": build_code_example_response(code_results),
            "tool_events": [
                {
                    "tool_name": "search_code_examples",
                    "arguments": {"query": last_user_text},
                    "result": {"results": code_results},
                }
            ],
            "memory_hits": [],
            "knowledge_hits": code_results,
            "model": "rule-based-defense",
        }

    if detect_attack_taxonomy_request(last_user_text) or detect_detection_rule_request(last_user_text):
        detection_results = search_detection_rules(last_user_text, limit=5)
        return {
            "reply": build_detection_rule_response(detection_results),
            "tool_events": [
                {
                    "tool_name": "search_detection_rules",
                    "arguments": {"query": last_user_text},
                    "result": {"results": detection_results},
                }
            ],
            "memory_hits": [],
            "knowledge_hits": detection_results,
            "model": "rule-based-defense",
        }

    if detect_cve_search_request(last_user_text):
        cve_results = search_cve_database(last_user_text, limit=5)
        return {
            "reply": build_cve_response(cve_results),
            "tool_events": [
                {
                    "tool_name": "search_cve_database",
                    "arguments": {"query": last_user_text, "limit": 5},
                    "result": {"results": cve_results},
                }
            ],
            "memory_hits": [],
            "knowledge_hits": cve_results,
            "model": "rule-based-defense",
        }

    if detect_site_prediction_request(last_user_text):
        prediction_args = extract_prediction_arguments(last_user_text)
        prediction_result = tool_predict_site_exposure(prediction_args)
        return {
            "reply": build_site_prediction_response(prediction_result),
            "tool_events": [
                {
                    "tool_name": "predict_site_exposure",
                    "arguments": prediction_args,
                    "result": prediction_result,
                }
            ],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "local-site-learning",
        }

    if detect_openvas_report_request(last_user_text):
        url = extract_target_url(last_user_text)
        try:
            report_result = tool_create_openvas_report_file({"url": url})
        except Exception as exc:
            return {
                "reply": build_site_analysis_error_reply(url or "requested target", str(exc)),
                "tool_events": [],
                "memory_hits": [],
                "knowledge_hits": [],
                "model": "rule-based-defense",
            }
        return {
            "reply": "\n".join(
                [
                    f"Saved cyber analysis report for requested URL: {url}",
                    f"Final analyzed URL: {report_result['url']}",
                    f"Severity: {report_result['severity']}",
                    f"Threat score: {report_result['threat_score']}/100",
                    f"Protection score: {report_result['protection_score']}/100",
                    f"Report path: {report_result['report_path']}",
                ]
            ),
            "tool_events": [
                {
                    "tool_name": "create_openvas_report_file",
                    "arguments": {"url": url},
                    "result": report_result,
                }
            ],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "rule-based-defense",
        }

    if detect_openvas_scan_request(last_user_text):
        url = extract_target_url(last_user_text)
        try:
            scan_result = tool_openvas_local_scan({"url": url})
        except Exception as exc:
            return {
                "reply": build_site_analysis_error_reply(url or "requested target", str(exc)),
                "tool_events": [],
                "memory_hits": [],
                "knowledge_hits": [],
                "model": "rule-based-defense",
            }
        return {
            "reply": build_openvas_local_response(scan_result),
            "tool_events": [
                {
                    "tool_name": "openvas_local_scan",
                    "arguments": {"url": url},
                    "result": scan_result,
                }
            ],
            "memory_hits": [],
            "knowledge_hits": scan_result.get("cve_matches", []),
            "model": "rule-based-defense",
        }

    if detect_url_report_request(last_user_text):
        url = extract_target_url(last_user_text)
        try:
            report_result = tool_create_url_report_file({"url": url})
        except Exception as exc:
            return {
                "reply": build_site_analysis_error_reply(url or "requested target", str(exc)),
                "tool_events": [],
                "memory_hits": [],
                "knowledge_hits": [],
                "model": "rule-based-defense",
            }
        return {
            "reply": "\n".join(
                [
                    f"Saved cyber analysis report for requested URL: {url}",
                    f"Final analyzed URL: {report_result['url']}",
                    f"Severity: {report_result['severity']}",
                    f"Threat score: {report_result['threat_score']}/100",
                    f"Report path: {report_result['report_path']}",
                ]
            ),
            "tool_events": [
                {
                    "tool_name": "create_url_report_file",
                    "arguments": {"url": url},
                    "result": report_result,
                }
            ],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "rule-based-defense",
        }

    if detect_url_threat_request(last_user_text):
        url = extract_target_url(last_user_text)
        try:
            url_result = tool_url_threat_report({"url": url})
        except Exception as exc:
            return {
                "reply": build_site_analysis_error_reply(url or "requested target", str(exc)),
                "tool_events": [],
                "memory_hits": [],
                "knowledge_hits": [],
                "model": "rule-based-defense",
            }
        return {
            "reply": build_url_threat_response(url_result),
            "tool_events": [
                {
                    "tool_name": "url_threat_report",
                    "arguments": {"url": url},
                    "result": url_result,
                }
            ],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "rule-based-defense",
        }

    if should_default_to_site_analysis(last_user_text):
        url = extract_target_url(last_user_text)
        try:
            url_result = tool_url_threat_report({"url": url})
        except Exception as exc:
            return {
                "reply": build_site_analysis_error_reply(url or "requested target", str(exc)),
                "tool_events": [],
                "memory_hits": [],
                "knowledge_hits": [],
                "model": "rule-based-defense",
            }
        return {
            "reply": build_url_threat_response(url_result),
            "tool_events": [
                {
                    "tool_name": "url_threat_report",
                    "arguments": {"url": url},
                    "result": url_result,
                }
            ],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "rule-based-defense",
        }

    if detect_learning_digest_request(last_user_text):
        digest = load_learning_digest()
        if digest:
            return {
                "reply": digest,
                "tool_events": [],
                "memory_hits": [],
                "knowledge_hits": [],
                "model": "local-learning-digest",
            }
        return {
            "reply": (
                "No three-day learning digest is available yet.\n\n"
                "Run `python3 auto_learn.py` once, or wait for the DarkTraceX autolearn job to collect a few feed snapshots."
            ),
            "tool_events": [],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "local-learning-digest",
        }

    if detect_phishing_examples_request(last_user_text):
        requested_limit = extract_requested_count(last_user_text, default=100, maximum=100)
        phishing_results = search_phishing_examples(last_user_text, limit=requested_limit)
        return {
            "reply": build_phishing_examples_response(phishing_results),
            "tool_events": [
                {
                    "tool_name": "search_phishing_examples",
                    "arguments": {"query": last_user_text, "limit": requested_limit},
                    "result": {"results_count": len(phishing_results)},
                }
            ],
            "memory_hits": [],
            "knowledge_hits": phishing_results[:5],
            "model": "rule-based-defense",
        }

    if detect_phishing_classification_request(last_user_text):
        result = classify_with_threshold("phishing_email", last_user_text)
        if not result["meets_threshold"]:
            heuristic = infer_phishing_label_from_flags(last_user_text)
            if heuristic:
                heuristic_result = {
                    "model": "local-nlp-heuristic",
                    "label": heuristic["label"],
                    "confidence": heuristic["confidence"],
                    "scores": [
                        {"label": heuristic["label"], "score": heuristic["confidence"]},
                    ],
                    "threshold": result["threshold"],
                    "meets_threshold": True,
                }
                return {
                    "reply": build_phishing_nlp_response(heuristic_result, last_user_text),
                    "tool_events": [{"tool_name": "classify_defense_text", "arguments": {"model": "phishing_email", "text": last_user_text}, "result": heuristic_result}],
                    "memory_hits": [],
                    "knowledge_hits": [],
                    "model": "local-nlp-heuristic",
                }
            detection_results = search_detection_rules("detect phishing", limit=3)
            return {
                "reply": build_detection_rule_response(detection_results),
                "tool_events": [{"tool_name": "classify_defense_text", "arguments": {"model": "phishing_email", "text": last_user_text}, "result": result}],
                "memory_hits": [],
                "knowledge_hits": detection_results,
                "model": "fallback-detection-rules",
            }
        return {
            "reply": build_phishing_nlp_response(result, last_user_text),
            "tool_events": [{"tool_name": "classify_defense_text", "arguments": {"model": "phishing_email", "text": last_user_text}, "result": result}],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "local-pattern-model",
        }

    if detect_log_analysis_request(last_user_text):
        result = classify_with_threshold("log_threat", last_user_text)
        if not result["meets_threshold"]:
            detection_results = search_detection_rules("detect brute force ransomware phishing", limit=4)
            return {
                "reply": build_detection_rule_response(detection_results),
                "tool_events": [{"tool_name": "classify_defense_text", "arguments": {"model": "log_threat", "text": last_user_text}, "result": result}],
                "memory_hits": [],
                "knowledge_hits": detection_results,
                "model": "fallback-detection-rules",
            }
        return {
            "reply": build_classifier_response(result),
            "tool_events": [{"tool_name": "classify_defense_text", "arguments": {"model": "log_threat", "text": last_user_text}, "result": result}],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "local-pattern-model",
        }

    if detect_attack_label_request(last_user_text):
        result = classify_with_threshold("attack_category", last_user_text)
        if not result["meets_threshold"]:
            detection_results = search_detection_rules(last_user_text, limit=4)
            return {
                "reply": build_detection_rule_response(detection_results),
                "tool_events": [{"tool_name": "classify_defense_text", "arguments": {"model": "attack_category", "text": last_user_text}, "result": result}],
                "memory_hits": [],
                "knowledge_hits": detection_results,
                "model": "fallback-detection-rules",
            }
        return {
            "reply": build_classifier_response(result),
            "tool_events": [{"tool_name": "classify_defense_text", "arguments": {"model": "attack_category", "text": last_user_text}, "result": result}],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "local-pattern-model",
        }

    memory_hits = search_notes(last_user_text, limit=4) if last_user_text else []
    knowledge_hits = search_knowledge(last_user_text, limit=4) if last_user_text else []
    rag_bundle = build_rag_bundle(last_user_text, memory_hits=memory_hits, knowledge_hits=knowledge_hits, limit=6)
    tool_events = []

    for _ in range(MAX_TOOL_STEPS):
        try:
            model_text, active_model = call_model(working_messages, memory_hits, knowledge_hits, tool_events, rag_bundle)
        except RuntimeError as exc:
            if MODEL_PROVIDER == "ollama":
                return {
                    "reply": build_offline_fallback(last_user_text, knowledge_hits, memory_hits, rag_bundle),
                    "tool_events": tool_events,
                    "memory_hits": memory_hits,
                    "knowledge_hits": knowledge_hits,
                    "model": "offline-retrieval",
                }
            raise exc
        tool_call = parse_tool_call(model_text) or extract_embedded_tool_call(model_text)

        if not tool_call:
            return {
                "reply": model_text,
                "tool_events": tool_events,
                "memory_hits": memory_hits,
                "knowledge_hits": knowledge_hits,
                "model": active_model,
            }

        tool_result = run_tool(tool_call["tool_name"], tool_call["arguments"])
        tool_events.append(tool_result)
        working_messages.append(
            {
                "role": "assistant",
                "text": f"Tool request: {json.dumps(tool_call)}",
            }
        )
        working_messages.append(
            {
                "role": "user",
                "text": f"Tool result: {json.dumps(tool_result)}",
            }
        )

    raise RuntimeError("Tool loop limit reached.")


def normalize_messages(raw_messages):
    normalized = []
    for message in raw_messages:
        role = message.get("role")
        text = (message.get("text") or "").strip()
        if role in {"user", "assistant"} and text:
            normalized.append({"role": role, "text": text})
    return normalized


class ChatHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _send_json(self, status_code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, status_code, body, content_type, filename=None):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/api/state":
            self._send_json(200, conversation_stats())
            return

        if parsed.path == "/api/export":
            self.handle_export_get(parsed.query)
            return

        return super().do_GET()

    def do_POST(self):
        if self.path == "/api/chat":
            self.handle_chat_post()
            return

        if self.path == "/api/notes":
            self.handle_note_post()
            return

        self._send_json(404, {"error": "Not found"})

    def handle_chat_post(self):
        try:
            payload = self.read_json_body()
            raw_messages = payload.get("messages") or []
            if not raw_messages and isinstance(payload.get("message"), str) and payload.get("message").strip():
                raw_messages = [{"role": "user", "text": payload.get("message").strip()}]
            messages = normalize_messages(raw_messages)
            conversation_id = payload.get("conversation_id")

            if not messages:
                self._send_json(400, {"error": "A non-empty messages array is required."})
                return

            conversation_id = ensure_conversation(conversation_id)

            latest = messages[-1]
            if latest["role"] == "user":
                save_message(conversation_id, "user", latest["text"])

            result = handle_chat(messages)
            save_message(
                conversation_id,
                "assistant",
                result["reply"],
                meta={
                    "tool_events": result["tool_events"],
                    "memory_hits": result["memory_hits"],
                },
            )
            self._send_json(
                200,
                {
                    "conversation_id": conversation_id,
                    "reply": result["reply"],
                    "tool_events": result["tool_events"],
                    "memory_hits": result["memory_hits"],
                    "knowledge_hits": result.get("knowledge_hits", []),
                    "stats": conversation_stats(),
                    "model": result.get("model", DEFAULT_MODEL),
                },
            )
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
        except RuntimeError as exc:
            message = str(exc)
            status_code = 500
            if message.startswith("Gemini API error (429):"):
                status_code = 429
            elif message.startswith("Gemini API error (401):"):
                status_code = 401
            self._send_json(status_code, {"error": message})
        except Exception as exc:
            traceback.print_exc()
            self._send_json(500, {"error": str(exc) or "Unexpected server error."})

    def handle_note_post(self):
        try:
            payload = self.read_json_body()
            content = payload.get("content", "")
            note = remember_note(content, source="manual")
            self._send_json(200, {"note": note, "stats": conversation_stats()})
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
        except RuntimeError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception:
            self._send_json(500, {"error": "Unexpected server error."})

    def read_json_body(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8")
        return json.loads(raw_body or "{}")

    def handle_export_get(self, query_string):
        try:
            params = urllib.parse.parse_qs(query_string)
            conversation_id = int((params.get("conversation_id") or [0])[0])
            export_format = (params.get("format") or ["markdown"])[0].lower()
            if conversation_id <= 0:
                self._send_json(400, {"error": "A valid conversation_id is required."})
                return
            if export_format not in {"markdown", "json"}:
                self._send_json(400, {"error": "format must be markdown or json."})
                return

            body_text, content_type, filename = build_conversation_export(conversation_id, export_format)
            self._send_bytes(200, body_text.encode("utf-8"), content_type, filename)
        except RuntimeError as exc:
            self._send_json(404, {"error": str(exc)})
        except Exception:
            self._send_json(500, {"error": "Unexpected server error."})


def main():
    global SSL_CONTEXT
    SSL_CONTEXT = build_ssl_context()
    init_db()
    seed_knowledge()
    load_defense_models()
    load_site_exposure_model()
    server = ThreadingHTTPServer((HOST, PORT), ChatHandler)
    print(f"Serving chatbot app at http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
