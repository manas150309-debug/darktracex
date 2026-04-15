from pathlib import Path

import torch
from torch import nn

from site_exposure_model import FEATURE_KEYS, LABELS, extract_site_features_from_row, label_from_row


class SiteExposureLSTM(nn.Module):
    def __init__(self, hidden_size=16, output_size=4):
        super().__init__()
        self.lstm = nn.LSTM(input_size=1, hidden_size=hidden_size, batch_first=True)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.ReLU(),
            nn.Linear(hidden_size, output_size),
        )

    def forward(self, x):
        output, _ = self.lstm(x)
        last = output[:, -1, :]
        return self.classifier(last)


def feature_sequence(row):
    feature_map = extract_site_features_from_row(row)
    return [float(feature_map[key]) for key in FEATURE_KEYS]


def train_lstm(samples, epochs=80, hidden_size=16, learning_rate=0.01):
    torch.manual_seed(13)
    model = SiteExposureLSTM(hidden_size=hidden_size, output_size=len(LABELS))
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.CrossEntropyLoss()

    inputs = torch.tensor([[[value] for value in feature_sequence(sample)] for sample in samples], dtype=torch.float32)
    targets = torch.tensor([LABELS.index(label_from_row(sample)) for sample in samples], dtype=torch.long)

    model.train()
    for _ in range(epochs):
        optimizer.zero_grad()
        logits = model(inputs)
        loss = criterion(logits, targets)
        loss.backward()
        optimizer.step()

    return {
        "model_name": "site_exposure_lstm",
        "feature_keys": FEATURE_KEYS,
        "labels": LABELS,
        "hidden_size": hidden_size,
        "state_dict": model.state_dict(),
        "training_samples": len(samples),
    }


def save_lstm_bundle(path, bundle):
    torch.save(bundle, Path(path))


def load_lstm_bundle(path):
    bundle = torch.load(Path(path), map_location="cpu")
    model = SiteExposureLSTM(hidden_size=bundle["hidden_size"], output_size=len(bundle["labels"]))
    model.load_state_dict(bundle["state_dict"])
    model.eval()
    bundle["model"] = model
    return bundle


def predict_lstm(bundle, feature_map):
    sequence = torch.tensor([[[float(feature_map[key])] for key in FEATURE_KEYS]], dtype=torch.float32)
    with torch.no_grad():
        logits = bundle["model"](sequence)
        probs = torch.softmax(logits, dim=1)[0].tolist()
    best_index = max(range(len(probs)), key=lambda idx: probs[idx])
    return {
        "label": bundle["labels"][best_index],
        "confidence": round(probs[best_index], 4),
        "scores": [{"label": bundle["labels"][idx], "score": round(score, 4)} for idx, score in enumerate(probs)],
    }
