from pathlib import Path

import joblib

from site_exposure_gnn import save_gnn_bundle, train_gnn
from site_exposure_lstm import save_lstm_bundle, train_lstm
from site_exposure_model import (
    augment_rows,
    load_training_rows,
    resolve_training_target_size,
    save_json_snapshot,
    train_mlp,
)


BASE_DIR = Path(__file__).resolve().parent
INPUT_CSV = BASE_DIR / "evaluation_report.csv"
SYNTHETIC_INPUT_CSV = BASE_DIR / "synthetic_evaluation_report.csv"
MODELS_DIR = BASE_DIR / "models"


def main():
    MODELS_DIR.mkdir(exist_ok=True)
    rows = load_training_rows(INPUT_CSV)
    synthetic_rows = load_training_rows(SYNTHETIC_INPUT_CSV) if SYNTHETIC_INPUT_CSV.exists() else []
    combined_rows = rows + synthetic_rows
    if not combined_rows:
        raise SystemExit(f"No successful rows available in {INPUT_CSV} or {SYNTHETIC_INPUT_CSV}")

    target_size = resolve_training_target_size(len(combined_rows), minimum=1000, multiplier=4, cap=5000)
    training_rows = augment_rows(combined_rows, target_size=target_size)

    mlp_model = train_mlp(training_rows)
    joblib.dump(mlp_model, MODELS_DIR / "site_exposure.joblib")
    save_json_snapshot(MODELS_DIR / "site_exposure.json", mlp_model)

    lstm_bundle = train_lstm(training_rows)
    save_lstm_bundle(MODELS_DIR / "site_exposure_lstm.pt", lstm_bundle)

    gnn_bundle = train_gnn(training_rows)
    save_gnn_bundle(MODELS_DIR / "site_exposure_gnn.pt", gnn_bundle)

    print(
        f"Trained MLP, LSTM, and GNN site exposure models from {len(rows)} real + {len(synthetic_rows)} synthetic rows "
        f"using {len(training_rows)} training samples into {MODELS_DIR}"
    )


if __name__ == "__main__":
    main()
