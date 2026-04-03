# Intrusion Detection System

This project is a machine-learning Intrusion Detection System built using a reduced **CICIDS2017** dataset. It trains an IDS model to detect malicious traffic, predicts attack type for detected attacks, and provides a simple Streamlit dashboard for monitoring replayed traffic logs. 

## Project Structure

```text
Intrusion-Detection-Sys/
├── train_model.py
├── capture.py
├── log_csv.py
├── dashboard.py
├── reduced_ids_dataset.csv
├── requirements.txt
├── README.md
├── live_logs.csv
├── alerts.csv
└── ids_model.pkl
```

## Overview

The project has four main parts:

1. **Model training**
   - `train_model.py` loads `reduced_ids_dataset.csv`
   - Cleans missing and infinite values
   - Normalizes labels
   - Trains:
     - a binary `XGBClassifier` for `BENIGN` vs `ATTACK`
     - an attack-type `XGBClassifier` for malicious classes only
   - Saves everything into `ids_model.pkl`

2. **Traffic replay / simulation**
   - `capture.py` replays rows from the reduced dataset as simulated live traffic
   - Uses the trained model bundle from `ids_model.pkl`
   - Supports:
     - configurable threshold
     - attack bursts
     - Gaussian feature perturbation
     - alert logging
     - consecutive-attack debouncing
     - optional ground-truth logging

3. **Dashboard**
   - `dashboard.py` reads `live_logs.csv` and `alerts.csv`
   - Shows:
     - total logged events
     - attack count
     - recent events
     - prediction distribution
     - attack-type distribution
     - alert panel
     - optional ground-truth distribution

## Dataset

This project uses a reduced CSV derived from **CICIDS2017**, stored as `reduced_ids_dataset.csv`.

### Label handling in training

- `BENIGN` is mapped to binary label `0`
- All other labels are mapped to binary label `1`

### Replay attack classes

The replay logic in `capture.py` is currently biased toward these demo attack labels when available:

- `DOS`
- `PORTSCAN`
- `WEBATTACK`

## Model Details

### Binary IDS model

- Model: `XGBClassifier`
- Purpose: classify traffic as benign or malicious

### Attack-type model

- Model: `XGBClassifier`
- Purpose: classify malicious traffic into attack categories

### Preprocessing

- `StandardScaler`
- `ColumnTransformer`
- `Pipeline`

### Evaluation used in training

- confusion matrix
- classification report
- F1-based threshold selection on hold-out data

## Requirements

- Python 3.9+
- Dependencies from `requirements.txt`

Install dependencies:

```cmd
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```  

## How to Run

### 1. Train the model

```cmd
python train_model.py
```

Optional custom threshold:

```cmd
python train_model.py --threshold 0.80
```

This generates `ids_model.pkl`.

### 2. Run simulated live detection

```cmd
python capture.py
```

Useful examples:

```cmd
python capture.py --log-ground-truth --reset-log
python capture.py --threshold 0.8 --attack-margin 0.05 --consecutive-attacks 2 --alerts
python capture.py --burst-prob 0.2 --burst-min 3 --burst-max 6
```

To see all replay options:

```cmd
python capture.py --help
```

### 3. Launch the dashboard

```cmd
streamlit run dashboard.py
```

The dashboard auto-refreshes and reads from `live_logs.csv` and `alerts.csv`.

## Typical Workflow

```cmd
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
pip install xgboost

python train_model.py
python capture.py --alerts --reset-log --reset-alerts
streamlit run dashboard.py
```

## Notes

- Run `train_model.py` before `capture.py`
- The current detection flow uses dataset replay, not full live packet feature extraction
- `log_csv.py` is used to safely append rows to CSV files while preserving headers

## License

This project is intended for educational and research purposes.