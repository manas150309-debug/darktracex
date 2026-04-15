# Project Concept

## Name

DarkTraceX

## Purpose

DarkTraceX is a local defensive cybersecurity assistant. It is built to help with:

- secure code review
- phishing analysis
- suspicious log analysis
- defensive attack detection guidance
- offline cybersecurity knowledge lookup

The project is designed to stay on the defensive side. It does not implement offensive exploitation workflows.

## Core Stack Used

- Frontend: plain HTML, CSS, JavaScript
- Backend: Python 3 standard library HTTP server
- Database: SQLite
- Local model runtime: Ollama
- Local model: `llama3.2:1b`
- Local ML persistence: `joblib`

## Main Files Used

- `server.py`: main backend, routing, tool execution, local model calls, rule-based handling
- `index.html`: UI structure
- `app.js`: frontend chat behavior, tool log, classifier panel
- `styles.css`: visual styling
- `assistant.db`: SQLite storage for messages, notes, and knowledge docs
- `README.md`: run instructions and project summary

## Data And Knowledge Sources Used

The chatbot uses offline JSON knowledge files stored in `data/` and seeds them into SQLite.

- `data/security_kb.json`: base security knowledge
- `data/code_fix_pairs.json`: insecure-to-secure code examples
- `data/cyber_attack_kb.json`: cyber attack categories and detection rules
- `data/attack_playbooks_kb.json`: larger defensive playbooks
- `data/phishing_examples_kb.json`: 100 phishing examples
- `data/ml_training_data.json`: local training data for classifiers

## Learning And Detection Used

This project uses two defensive reasoning layers:

1. Rule-based detection

- catches obvious credential theft and phishing patterns
- catches obvious SQL injection patterns
- routes some requests directly to stored datasets instead of relying on the model

2. Local pattern-learning classifiers

- phishing email classification
- log threat classification
- attack category classification
- code security classification

The classifiers are lightweight local models, not deep neural networks. They are stored in `models/`.

## Local Models Used

Saved under `models/`:

- `phishing_email.joblib`
- `log_threat.joblib`
- `attack_category.joblib`
- `code_security.joblib`

Training script used:

- `train_defense_models.py`

Training data generator used:

- `generate_ml_training_data.py`

## Defensive Tools Used

The backend exposes these tool capabilities:

- `remember_note`
- `search_notes`
- `search_knowledge`
- `search_code_examples`
- `search_detection_rules`
- `search_phishing_examples`
- `classify_defense_text`
- `dns_lookup`
- `reverse_dns`
- `http_headers`
- `security_headers_audit`
- `tls_inspect`

## Extra Generators And Utilities Used

- `generate_code_examples.py`
- `generate_attack_knowledge.py`
- `generate_attack_playbooks.py`
- `generate_phishing_examples.py`
- `bulk_audit.py`

## Reports And Evaluation Files Used

- `REPORT.csv`
- `report.txt`
- `report.pdf`
- `authorized_sites.csv`
- `evaluation_report.csv`

## How The Project Works

1. The frontend sends chat messages to `/api/chat`.
2. The backend checks for rule-based matches first.
3. If needed, it searches the local SQLite knowledge base.
4. If needed, it uses local classifiers.
5. If needed, it calls the local Ollama model.
6. Results are returned to the frontend and stored in SQLite.

## Current Architecture Summary

- local-first
- offline-capable
- SQLite-backed
- Ollama-backed
- defensive only
- dataset-enhanced
- classifier-assisted

## Current Goal Of The Project

To provide a local cybersecurity assistant that can:

- explain threats in simple language
- analyze suspicious input safely
- provide secure code guidance
- return stored examples directly when possible
- work without an external API key
