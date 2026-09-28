# Waqqas IDS — Setup

## Requirements

- Python 3.11 or newer
- NSL-KDD files in `data/`: `KDDTrain+.TXT`, `KDDTest+.TXT`

## Install

```powershell
cd G:\WAQQAS_IDS
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -r requirements.txt
```

If `.venv` was copied from another PC and `python` inside it fails, delete `.venv` and recreate it with the commands above.

## Run

```powershell
$env:FLASK_USE_RELOADER = "0"
python app.py
```

Open http://127.0.0.1:5000 — default access key: `waqqas` (override with `WAQQAS_ACCESS_KEY`).

## Train models (CLI)

```powershell
python train_models.py
```

Metrics are written to `reports/training_summary.json` for the Analysis page.
