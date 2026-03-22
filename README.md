# Network Intrusion Detection System (NIDS)

An end-to-end machine learning pipeline for network traffic analysis and threat detection. This project utilizes a two-stage **XGBoost** approach to classify traffic as Benign or Malicious, and then further categorizes detected attacks into specific types.

## 📂 Project Structure

```plaintext
Intrusion-Detection-Sys/
├── train_model.py          # Data preprocessing and model training logic
├── ids_inference.py        # Helper functions for thresholding and inference
├── capture.py              # Traffic replay and simulation engine
├── log_csv.py              # Thread-safe CSV logging utility
├── dashboard.py            # Streamlit-based monitoring dashboard
├── reduced_ids_dataset.csv # Processed CICIDS2017 dataset
├── capture.pcap            # Sample packet capture (for reference)
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
├── live_logs.csv           # Runtime log of processed traffic
├── alerts.csv              # Runtime log of detected threats
└── ids_model.pkl           # Exported model bundle (Binary + Attack-type)
```

---

## 🚀 Overview

The system consists of four primary components:

1.  **Model Training (`train_model.py`):** Cleans missing/infinite values from the `CICIDS2017` dataset and trains a dual-model pipeline (Binary Classification + Multiclass Attack classification).
2.  **Inference Utilities (`ids_inference.py`):** Provides the logic for extracting attack probabilities and applying a "threshold floor" to minimize false positives.
3.  **Traffic Simulation (`capture.py`):** Replays data from the CSV as if it were live traffic. It supports advanced features like **Gaussian feature perturbation** and **attack bursts**.
4.  **Dashboard (`dashboard.py`):** A real-time Streamlit UI that visualizes traffic distributions, attack types, and alert panels.
---

## 🛠️ Installation
### Prerequisites* Python 3.9+
### Setup```bash# Create and activate virtual environmentpython -m venv .venv# On Windows: .\venv\Scripts\activate# On macOS/Linux: source .venv/bin/activate# Install dependenciespip install -r requirements.txt pip install xgboost```> **Note:** `xgboost` must be installed manually if it is not yet added to your `requirements.txt`.
---

## 🚦 How to Run
### 1. Train the ModelThis step generates the `ids_model.pkl` file required for detection.```bashpython train_model.py --threshold 0.80```### 2. Run Simulated Live DetectionReplays the dataset to simulate network traffic and logs results to CSV files.# Basic run with alerts```bashpython capture.py --alerts --reset-log --reset-alerts```# Advanced simulation with attack bursts and debouncing```bashpython capture.py --threshold 0.8 --burst-prob 0.2 --consecutive-attacks 2```### 3. Launch the DashboardView the live results in your browser.`streamlit run dashboard.py`---
## 📊 Model Details### Detection Logic* **Binary Model:** `XGBClassifier` used to flag traffic as `BENIGN` (0) or `ATTACK` (1).* **Attack-Type Model:** A secondary `XGBClassifier` that triggers only when an attack is detected, classifying it into categories like **DoS**, **PortScan**, or **WebAttack**.
### Preprocessing Pipeline* **StandardScaler:** Normalizes feature scales.* **ColumnTransformer:** Handles specific column types.* **F1-Score Optimization:** Thresholds are selected based on the best F1-score on hold-out data.
---
## 📝 Notes* **Dataset:** This project uses a reduced version of the **CICIDS2017** dataset.* **Simulated Flow:** While the repository contains a `.pcap` file and `scapy` is a dependency, the current detection flow is driven by **CSV dataset replay** rather than raw packet sniffing.* **Logging:** `log_csv.py` ensures that the dashboard can read `live_logs.csv` and `alerts.csv` even while the simulation is actively writing to them.
---
## ⚖️ LicenseThis project is intended for educational and research purposes.
---
**Would you like me to generate a `requirements.txt` file for you based on these scripts?**
