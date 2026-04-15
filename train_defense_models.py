import json
from collections import Counter, defaultdict
from pathlib import Path

import joblib


BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "ml_training_data.json"
MODELS_DIR = BASE_DIR / "models"


def tokenize(text):
    import re
    return [token for token in re.findall(r"[a-zA-Z0-9_@./:-]{2,}", (text or "").lower())]


def train_model(name, samples):
    labels = sorted({sample["label"] for sample in samples})
    priors = {}
    token_counts = defaultdict(Counter)
    total_tokens = Counter()
    vocabulary = set()

    label_counts = Counter(sample["label"] for sample in samples)
    sample_count = len(samples)
    for label in labels:
        priors[label] = label_counts[label] / sample_count

    for sample in samples:
        label = sample["label"]
        tokens = tokenize(sample["text"])
        token_counts[label].update(tokens)
        total_tokens[label] += len(tokens)
        vocabulary.update(tokens)

    return {
        "model_name": name,
        "labels": labels,
        "priors": dict(priors),
        "token_counts": {label: dict(counts) for label, counts in token_counts.items()},
        "total_tokens": dict(total_tokens),
        "vocabulary": sorted(vocabulary),
    }


def main():
    raw = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    MODELS_DIR.mkdir(exist_ok=True)
    for model_name, samples in raw.items():
        payload = train_model(model_name, samples)
        joblib.dump(payload, MODELS_DIR / f"{model_name}.joblib")
    print(f"Trained {len(raw)} local defensive models into {MODELS_DIR}")


if __name__ == "__main__":
    main()
