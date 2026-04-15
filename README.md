# DarkTraceX Console

Defensive cybersecurity chatbot with:

- SQLite persistence for conversations, notes, and offline knowledge
- Offline-first defensive analysis
- A local Ollama model path with no external API key requirement
- Browser session persistence and a dark console UI
- Transcript export in Markdown or JSON

## What it does

- Saves chat messages in `assistant.db`
- Stores and searches internal notes
- Seeds an offline security knowledge base from `data/security_kb.json`
- Runs defensive-only local tools such as:
  - `search_knowledge`
  - `search_code_examples`
  - `search_detection_rules`
  - `search_phishing_examples`
  - `classify_defense_text`
  - cached URL and OpenVAS-style report lookup

## Run it

```bash
cd /Users/manas/Desktop/chatbot
export MODEL_PROVIDER="ollama"
export MODEL_NAME="llama3.2:1b"
export OFFLINE_MODE="1"
python3 server.py
```

Open `http://127.0.0.1:8000`

## Startup Learning And Three-Day Digest

DarkTraceX can now run a safe local autolearn job on macOS login and then refresh every 6 hours.

What it does:

- reads curated security feed URLs from `data/learning_sources.json`
- fetches and classifies feed items into simple categories
- stores snapshots under `reports/learning/`
- builds a plain-language digest at:
  - `reports/three-day-learning-digest.md`
  - `reports/three-day-learning-digest.json`
- lets the chatbot answer prompts such as:
  - `show learning digest`
  - `what did you learn`
  - `latest trends`

Files added:

- `auto_learn.py`
- `build_learning_digest.py`
- `scripts/run_autolearn.sh`
- `~/Library/LaunchAgents/com.darktracex.autolearn.plist`

To trigger it manually once:

```bash
cd /Users/manas/Desktop/chatbot
python3 auto_learn.py
```

The LaunchAgent is configured with:

- `RunAtLoad = true`
- `StartInterval = 21600` seconds

That means the learning job runs when you log in and then again every 6 hours. After a few runs, the three-day digest becomes more useful.

## Tooling

Node.js is installed locally for frontend checks. Project scripts:

```bash
cd /Users/manas/Desktop/chatbot
npm install
npm run check
npm run healthcheck
```

Available checks:

- `npm run check:js`
- `npm run lint:js`
- `npm run check:py`
- `npm run format:check`
- `npm run healthcheck`

## Batch URL Reports

For websites you own or are explicitly permitted to assess:

```bash
cd /Users/manas/Desktop/chatbot
python3 batch_url_reports.py
```

Outputs:

- `evaluation_report.csv`
- `reports/batch_summary.md`
- one markdown report per target under `reports/`

If you want the models to learn from a larger approved dataset, put up to 1000 authorized targets in `authorized_sites.csv`, generate `evaluation_report.csv`, then retrain the models.

For safe local experimentation without scanning third-party targets, you can also generate a synthetic website training corpus:

```bash
cd /Users/manas/Desktop/chatbot
python3 generate_synthetic_site_training_data.py
python3 train_all_site_models.py
```

## Offline-Only Mode

DarkTraceX now runs in offline-only mode by default.

What this means:

- no live DNS lookups
- no live HTTP or TLS probing
- no external API usage
- no live website scanning
- local Ollama inference is still allowed because it is fully local

For website analysis, DarkTraceX uses cached local reports already stored under `reports/`.

## OpenVAS-Style Local Scanner

The project includes an OpenVAS-style local scanner interface that works from cached offline reports.

Try prompts such as:

- `openvas scan example.com`
- `create openvas report for example.com`

What it uses offline:

- cached report markdown under `reports/`
- offline CVE hints from the local database
- local learned assessment models
- saved threat graph data from prior local reports

Report output:

- markdown reports are written under `reports/`
- example file pattern: `reports/example.com-openvas-local.md`

Important limit:

- in offline-only mode, it cannot fetch fresh website data
- analysis only works for targets that already have a cached local report

## Local Multi-Model Routing

The backend can route different prompt types to different local Ollama models if they are already installed on your machine.

Optional environment variables:

```bash
export OLLAMA_GENERAL_MODEL="llama3.2:1b"
export OLLAMA_ANALYSIS_MODEL="llama3.2:1b"
export OLLAMA_CODE_MODEL="llama3.2:1b"
```

Current behavior:

- general chat uses `OLLAMA_GENERAL_MODEL`
- URL, phishing, log, and report-style prompts use `OLLAMA_ANALYSIS_MODEL`
- code-oriented prompts use `OLLAMA_CODE_MODEL`

## Authorized Site Learning

The project can train a local site-exposure model from your authorized website reports only.

```bash
cd /Users/manas/Desktop/chatbot
python3 batch_url_reports.py
python3 train_site_exposure_model.py
python3 train_site_exposure_lstm.py
python3 train_site_exposure_gnn.py
python3 train_all_site_models.py
```

What it does:

- reads `evaluation_report.csv`
- can also combine `synthetic_evaluation_report.csv` for safe local training expansion
- extracts passive website features
- trains a small local neural-network-style classifier
- trains a local LSTM classifier if PyTorch is available
- trains a local graph-neural-network-style classifier if PyTorch is available
- loads the MLP, LSTM, and GNN models into URL threat reports and dataset prediction when available
- scales augmentation toward a 1000-row authorized training set when enough approved targets are supplied

## Fortune Company Starter Directory

The repo now includes a local starter company directory in:

- `data/fortune_company_directory.json`

That lets prompts such as:

- `cyber analysis of Microsoft`
- `create report for Walmart`

resolve to the mapped public company website without automatic bulk scanning.

## Export Conversations

Use the `Export MD` or `Export JSON` buttons in the UI after a conversation exists.

- Markdown export is useful for readable reports
- JSON export is useful for tooling or later processing

## Notes

- The database file is `assistant.db`
- `.gitignore` excludes the local database, model files, and cache artifacts from Git commits
- The offline knowledge seed file is `data/security_kb.json`
- Additional code-fix training examples can be generated into `data/code_fix_pairs.json`
- If the local model is unavailable, the app can still answer from offline retrieval over notes and the local knowledge base
- The tool layer is defensive only. It does not implement exploitation or intrusive attack workflows

## Bulk Evaluation

Use `authorized_sites.csv` for websites you own or are explicitly permitted to assess, then run:

```bash
cd /Users/manas/Desktop/chatbot
python3 bulk_audit.py
```

The report is written to `evaluation_report.csv`.

## Generate 100 Secure Fix Examples

```bash
cd /Users/manas/Desktop/chatbot
python3 generate_code_examples.py
```

This writes `data/code_fix_pairs.json` with 100 insecure-to-secure defensive code examples across common vulnerability classes.

## Generate Cyber Attack Taxonomy And Detection Rules

```bash
cd /Users/manas/Desktop/chatbot
python3 generate_attack_knowledge.py
```

This writes `data/cyber_attack_kb.json` with offline attack categories and detection guidance.

## Generate Extended Attack Playbooks

```bash
cd /Users/manas/Desktop/chatbot
python3 generate_attack_playbooks.py
```

This writes `data/attack_playbooks_kb.json` with large-scale defensive playbook entries so the local knowledge base can exceed 500 documents.

## Generate 100 Phishing Examples

```bash
cd /Users/manas/Desktop/chatbot
python3 generate_phishing_examples.py
```

This writes `data/phishing_examples_kb.json` with 100 stored phishing examples for direct retrieval.

For the current system-level evaluation summary, use:

- `REPORT.csv`
