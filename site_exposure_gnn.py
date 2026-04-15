from pathlib import Path

import torch
from torch import nn

from site_exposure_model import FEATURE_KEYS, LABELS, extract_site_features_from_row, label_from_row


EDGE_GROUPS = [
    ("threat_score", "protection_score"),
    ("threat_score", "status_ok"),
    ("threat_score", "tls_days_remaining"),
    ("protection_score", "status_ok"),
    ("protection_score", "tls_days_remaining"),
    ("missing_hsts", "missing_csp"),
    ("missing_hsts", "missing_xcto"),
    ("missing_hsts", "missing_referrer_policy"),
    ("missing_csp", "missing_frame_controls"),
    ("missing_csp", "server_header_exposed"),
    ("missing_frame_controls", "server_header_exposed"),
    ("missing_xcto", "server_header_exposed"),
]


def build_adjacency():
    size = len(FEATURE_KEYS)
    index_by_name = {name: idx for idx, name in enumerate(FEATURE_KEYS)}
    adjacency = torch.eye(size, dtype=torch.float32)
    for left, right in EDGE_GROUPS:
        left_idx = index_by_name[left]
        right_idx = index_by_name[right]
        adjacency[left_idx, right_idx] = 1.0
        adjacency[right_idx, left_idx] = 1.0
    degrees = adjacency.sum(dim=1)
    inv_sqrt = torch.diag(torch.pow(degrees, -0.5))
    return inv_sqrt @ adjacency @ inv_sqrt


class GraphConvLayer(nn.Module):
    def __init__(self, in_features, out_features):
        super().__init__()
        self.linear = nn.Linear(in_features, out_features)

    def forward(self, node_features, adjacency):
        propagated = torch.matmul(adjacency, node_features)
        return self.linear(propagated)


class SiteExposureGNN(nn.Module):
    def __init__(self, hidden_size=16, output_size=4):
        super().__init__()
        self.input_projection = nn.Linear(1, hidden_size)
        self.conv1 = GraphConvLayer(hidden_size, hidden_size)
        self.conv2 = GraphConvLayer(hidden_size, hidden_size)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.ReLU(),
            nn.Linear(hidden_size, output_size),
        )

    def forward(self, x, adjacency):
        hidden = torch.relu(self.input_projection(x))
        hidden = torch.relu(self.conv1(hidden, adjacency))
        hidden = torch.relu(self.conv2(hidden, adjacency))
        pooled = hidden.mean(dim=1)
        return self.classifier(pooled)


def feature_graph(row):
    feature_map = extract_site_features_from_row(row)
    return [[float(feature_map[key])] for key in FEATURE_KEYS]


def train_gnn(samples, epochs=100, hidden_size=16, learning_rate=0.01):
    torch.manual_seed(17)
    model = SiteExposureGNN(hidden_size=hidden_size, output_size=len(LABELS))
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.CrossEntropyLoss()

    adjacency = build_adjacency()
    inputs = torch.tensor([feature_graph(sample) for sample in samples], dtype=torch.float32)
    targets = torch.tensor([LABELS.index(label_from_row(sample)) for sample in samples], dtype=torch.long)

    model.train()
    for _ in range(epochs):
        optimizer.zero_grad()
        logits = model(inputs, adjacency)
        loss = criterion(logits, targets)
        loss.backward()
        optimizer.step()

    return {
        "model_name": "site_exposure_gnn",
        "feature_keys": FEATURE_KEYS,
        "labels": LABELS,
        "hidden_size": hidden_size,
        "edge_groups": EDGE_GROUPS,
        "state_dict": model.state_dict(),
        "training_samples": len(samples),
    }


def save_gnn_bundle(path, bundle):
    torch.save(bundle, Path(path))


def load_gnn_bundle(path):
    bundle = torch.load(Path(path), map_location="cpu")
    model = SiteExposureGNN(hidden_size=bundle["hidden_size"], output_size=len(bundle["labels"]))
    model.load_state_dict(bundle["state_dict"])
    model.eval()
    bundle["model"] = model
    bundle["adjacency"] = build_adjacency()
    return bundle


def predict_gnn(bundle, feature_map):
    graph = torch.tensor([[[float(feature_map[key])] for key in FEATURE_KEYS]], dtype=torch.float32)
    with torch.no_grad():
        logits = bundle["model"](graph, bundle["adjacency"])
        probs = torch.softmax(logits, dim=1)[0].tolist()
    best_index = max(range(len(probs)), key=lambda idx: probs[idx])
    return {
        "label": bundle["labels"][best_index],
        "confidence": round(probs[best_index], 4),
        "scores": [{"label": bundle["labels"][idx], "score": round(score, 4)} for idx, score in enumerate(probs)],
    }
