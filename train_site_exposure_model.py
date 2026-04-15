from pathlib import Path

import joblib

from site_exposure_model import (
    augment_rows,
    load_training_rows,
    resolve_training_target_size,
    save_json_snapshot,
    train_mlp,
)


BASE_DIR = Path(__file__).resolve().parent
INPUT_CSV = BASE_DIR / "evaluation_report.csv"
MODELS_DIR = BASE_DIR / "models"


def main():
    MODELS_DIR.mkdir(exist_ok=True)
    rows = load_training_rows(INPUT_CSV)
    if not rows:
        raise SystemExit(f"No successful rows available in {INPUT_CSV}")

    training_rows = augment_rows(rows, target_size=resolve_training_target_size(len(rows)))
    model = train_mlp(training_rows)
    joblib.dump(model, MODELS_DIR / "site_exposure.joblib")
    save_json_snapshot(MODELS_DIR / "site_exposure.json", model)
    print(f"Trained site exposure model from {len(rows)} authorized rows into {MODELS_DIR}")


if __name__ == "__main__":
    main()
