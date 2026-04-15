from pathlib import Path

from site_exposure_lstm import save_lstm_bundle, train_lstm
from site_exposure_model import augment_rows, load_training_rows, resolve_training_target_size


BASE_DIR = Path(__file__).resolve().parent
INPUT_CSV = BASE_DIR / "evaluation_report.csv"
MODELS_DIR = BASE_DIR / "models"


def main():
    MODELS_DIR.mkdir(exist_ok=True)
    rows = load_training_rows(INPUT_CSV)
    if not rows:
        raise SystemExit(f"No successful rows available in {INPUT_CSV}")

    training_rows = augment_rows(rows, target_size=resolve_training_target_size(len(rows)))
    bundle = train_lstm(training_rows)
    save_lstm_bundle(MODELS_DIR / "site_exposure_lstm.pt", bundle)
    print(f"Trained LSTM site exposure model from {len(rows)} authorized rows into {MODELS_DIR}")


if __name__ == "__main__":
    main()
