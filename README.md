# Intrusion Detection System

This project is a lightweight machine-learning Intrusion Detection System built using a reduced **CICIDS2017** dataset. It trains an IDS model to detect malicious traffic, predicts attack type for detected attacks, and provides a simple Streamlit dashboard for monitoring replayed traffic logs.

## Project Structure

```text
Intrusion-Detection-Sys/
├── train_model.py
├── ids_inference.py
├── capture.py
├── log_csv.py
├── dashboard.py
├── reduced_ids_dataset.csv
├── capture.pcap
├── requirements.txt
├── README.md
├── live_logs.csv          # generated at runtime
├── alerts.csv             # generated at runtime
└── ids_model.pkl          # generated after training


Overview
The project has four main parts:

Model training

train_model.py loads reduced_ids_dataset.csv
Cleans missing and infinite values
Normalizes labels
Trains:
a binary XGBoost model for BENIGN vs ATTACK
an attack-type XGBoost model for malicious classes only
Saves everything into ids_model.pkl
Inference utilities

ids_inference.py provides helper functions for:
extracting attack probability from the binary model
resolving the threshold used for attack decisions
Includes a default threshold floor to reduce false positives
Traffic replay / simulation

capture.py replays rows from the reduced dataset as simulated live traffic
Uses the trained model bundle from ids_model.pkl
Supports:
configurable threshold
attack bursts
Gaussian feature perturbation
alert logging
consecutive-attack debouncing
optional ground-truth logging
Dashboard

dashboard.py reads live_logs.csv and alerts.csv
Shows:
total logged events
attack count
recent events
prediction distribution
attack-type distribution
alert panel
optional ground-truth distribution
Dataset
This project uses a reduced CSV derived from CICIDS2017, stored as:

reduced_ids_dataset.csv
Label handling in training
BENIGN is mapped to binary label 0
All other labels are mapped to binary label 1
BENIGN, NORMAL, and OTHER are excluded from the attack-type model
Replay attack classes
The replay logic in capture.py is currently biased toward these demo attack labels when available:

DOS
PORTSCAN
WEBATTACK
Model Details
Binary IDS model
Model: XGBClassifier
Purpose: classify traffic as benign or malicious
Attack-type model
Model: XGBClassifier
Purpose: classify malicious traffic into attack categories
Preprocessing
StandardScaler
ColumnTransformer
Pipeline
Evaluation used in training
confusion matrix
classification report
F1-based threshold selection on hold-out data
Requirements
Python 3.9+
Dependencies from requirements.txt
Install dependencies:

python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
pip install xgboost
Note: train_model.py imports xgboost, but it is not listed in requirements.txt, so install it manually unless you add it there.

How to Run
1. Train the model
python train_model.py
Optional custom threshold:

python train_model.py --threshold 0.80
This generates:

ids_model.pkl
2. Run simulated live detection
python capture.py
Useful examples:

python capture.py --log-ground-truth --reset-log
python capture.py --threshold 0.8 --attack-margin 0.05 --consecutive-attacks 2 --alerts
python capture.py --burst-prob 0.2 --burst-min 3 --burst-max 6
To see all replay options:

python capture.py --help
3. Launch the dashboard
streamlit run dashboard.py
The dashboard auto-refreshes and reads from:

live_logs.csv
alerts.csv
Typical Workflow
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
pip install xgboost

python train_model.py
python capture.py --alerts --reset-log --reset-alerts
streamlit run dashboard.py
Notes
Run train_model.py before capture.py
The current detection flow uses dataset replay, not full live packet feature extraction
capture.pcap exists in the repository, but the active IDS flow is driven by CSV replay
scapy is installed, but the main implemented demo path uses the reduced dataset and dashboard logs
log_csv.py is used to safely append rows to CSV files while preserving headers
License
This project is intended for educational and research purposes.