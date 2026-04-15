import csv
import json
import math
import random
from pathlib import Path


FEATURE_KEYS = [
    "threat_score",
    "protection_score",
    "status_ok",
    "tls_days_remaining",
    "missing_hsts",
    "missing_csp",
    "missing_xcto",
    "missing_referrer_policy",
    "missing_frame_controls",
    "server_header_exposed",
]

LABELS = ["low", "medium", "high", "critical"]


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def extract_site_features_from_row(row):
    findings = (row.get("findings") or "").lower()
    threat_score = _safe_float(row.get("threat_score"), 0.0)
    protection_score = _safe_float(row.get("protection_score"), 0.0)
    status = int(_safe_float(row.get("status"), 0.0))
    tls_days = _safe_float(row.get("tls_days_remaining"), 0.0)

    return {
        "threat_score": min(max(threat_score / 100.0, 0.0), 1.0),
        "protection_score": min(max(protection_score / 100.0, 0.0), 1.0),
        "status_ok": 1.0 if 200 <= status < 400 else 0.0,
        "tls_days_remaining": min(max(tls_days / 365.0, 0.0), 1.0),
        "missing_hsts": 1.0 if "missing hsts" in findings else 0.0,
        "missing_csp": 1.0 if "missing content-security-policy" in findings else 0.0,
        "missing_xcto": 1.0 if "missing x-content-type-options" in findings else 0.0,
        "missing_referrer_policy": 1.0 if "missing referrer-policy" in findings else 0.0,
        "missing_frame_controls": 1.0 if "x-frame-options" in findings or "frame-ancestors" in findings else 0.0,
        "server_header_exposed": 1.0 if "server header exposed" in findings else 0.0,
    }


def vectorize(feature_map):
    return [float(feature_map.get(key, 0.0)) for key in FEATURE_KEYS]


def label_from_row(row):
    severity = (row.get("severity") or "").strip().lower()
    if severity in LABELS:
        return severity

    threat_score = _safe_float(row.get("threat_score"), 0.0)
    if threat_score >= 75:
        return "critical"
    if threat_score >= 55:
        return "high"
    if threat_score >= 30:
        return "medium"
    return "low"


def load_training_rows(csv_path):
    rows = []
    with Path(csv_path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if (row.get("error") or "").strip():
                continue
            rows.append(row)
    return rows


def augment_rows(rows, target_size=64):
    if not rows:
        return []
    augmented = list(rows)
    random.seed(7)
    while len(augmented) < target_size:
        base = dict(random.choice(rows))
        threat = _safe_float(base.get("threat_score"), 0.0)
        protection = _safe_float(base.get("protection_score"), 0.0)
        tls_days = _safe_float(base.get("tls_days_remaining"), 0.0)
        jitter = random.uniform(-6, 6)
        base["threat_score"] = str(max(0.0, min(100.0, threat + jitter)))
        base["protection_score"] = str(max(0.0, min(100.0, protection - jitter)))
        if tls_days:
            base["tls_days_remaining"] = str(max(0.0, tls_days + random.uniform(-15, 15)))
        augmented.append(base)
    return augmented


def resolve_training_target_size(row_count, minimum=1000, multiplier=4, cap=5000):
    if row_count <= 0:
        return minimum
    return min(cap, max(minimum, row_count * multiplier))


def _init_matrix(rows, cols):
    scale = 0.25
    return [[random.uniform(-scale, scale) for _ in range(cols)] for _ in range(rows)]


def _softmax(values):
    peak = max(values)
    exps = [math.exp(value - peak) for value in values]
    total = sum(exps) or 1.0
    return [value / total for value in exps]


def train_mlp(samples, epochs=260, learning_rate=0.08, hidden_size=12):
    random.seed(11)
    input_size = len(FEATURE_KEYS)
    output_size = len(LABELS)
    w1 = _init_matrix(hidden_size, input_size)
    b1 = [0.0] * hidden_size
    w2 = _init_matrix(output_size, hidden_size)
    b2 = [0.0] * output_size

    indexed = [(vectorize(extract_site_features_from_row(row)), LABELS.index(label_from_row(row))) for row in samples]

    for _ in range(epochs):
        random.shuffle(indexed)
        for features, label_index in indexed:
            hidden_pre = [sum(weight * value for weight, value in zip(row, features)) + bias for row, bias in zip(w1, b1)]
            hidden = [math.tanh(value) for value in hidden_pre]
            output_pre = [sum(weight * value for weight, value in zip(row, hidden)) + bias for row, bias in zip(w2, b2)]
            probs = _softmax(output_pre)

            grad_out = probs[:]
            grad_out[label_index] -= 1.0

            for output_idx in range(output_size):
                for hidden_idx in range(hidden_size):
                    w2[output_idx][hidden_idx] -= learning_rate * grad_out[output_idx] * hidden[hidden_idx]
                b2[output_idx] -= learning_rate * grad_out[output_idx]

            grad_hidden = []
            for hidden_idx in range(hidden_size):
                downstream = sum(w2[output_idx][hidden_idx] * grad_out[output_idx] for output_idx in range(output_size))
                grad_hidden.append(downstream * (1.0 - hidden[hidden_idx] ** 2))

            for hidden_idx in range(hidden_size):
                for input_idx in range(input_size):
                    w1[hidden_idx][input_idx] -= learning_rate * grad_hidden[hidden_idx] * features[input_idx]
                b1[hidden_idx] -= learning_rate * grad_hidden[hidden_idx]

    return {
        "model_name": "site_exposure",
        "labels": LABELS,
        "feature_keys": FEATURE_KEYS,
        "hidden_size": hidden_size,
        "w1": w1,
        "b1": b1,
        "w2": w2,
        "b2": b2,
        "training_samples": len(samples),
    }


def predict_mlp(model, feature_map):
    features = vectorize(feature_map)
    hidden_pre = [sum(weight * value for weight, value in zip(row, features)) + bias for row, bias in zip(model["w1"], model["b1"])]
    hidden = [math.tanh(value) for value in hidden_pre]
    output_pre = [sum(weight * value for weight, value in zip(row, hidden)) + bias for row, bias in zip(model["w2"], model["b2"])]
    probs = _softmax(output_pre)
    best_index = max(range(len(probs)), key=lambda idx: probs[idx])
    return {
        "label": model["labels"][best_index],
        "confidence": round(probs[best_index], 4),
        "scores": [{"label": model["labels"][idx], "score": round(score, 4)} for idx, score in enumerate(probs)],
    }


def save_json_snapshot(path, model):
    Path(path).write_text(json.dumps(model, indent=2), encoding="utf-8")
