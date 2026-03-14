# Intrusion-Detection-Sys

A simple network intrusion detection system using NSL-KDD data for training and live packet capture for inference.

**Project Structure**
- `dataset/` - NSL-KDD CSV files used for training and testing.
- `ids_model.pkl` - Trained model artifact created by `train_model.py`.
- `train_model.py` - Trains the IDS model and saves `ids_model.pkl`.
- `realtime_capture.py` - Captures live packets and prints predictions.
- `dashboard.py` - Streamlit dashboard that visualizes `traffic_log.csv`.
- `traffic_log.csv` - Sample or expected log file for the dashboard.

**Requirements**
- Python 3.9+ recommended
- Packages: `pandas`, `numpy`, `scikit-learn`, `joblib`, `scapy`, `streamlit`
- Windows users may need Npcap installed for `scapy` packet capture.
- Packet capture usually requires running the terminal as Administrator.

**Setup (Windows cmd)**
```cmd
python -m venv .venv
.\.venv\Scripts\activate
pip install pandas numpy scikit-learn joblib scapy streamlit

Dataset
Place the NSL-KDD files here:

dataset\NSL_KDD_Train.csv
dataset\NSL_KDD_Test.csv
Note: train_model.py currently loads the dataset from ..\ids\dataset\.... In this repo the dataset is in dataset\..., so update the two paths in train_model.py or run the script from a folder where ..\ids\dataset\ exists.

Train the Model

python train_model.py
This generates ids_model.pkl in the project root.

Run Real-Time Capture

python realtime_capture.py
The script loads ids_model.pkl and prints alerts to the console.

Run the Dashboard

streamlit run dashboard.py
The dashboard reads traffic_log.csv and refreshes every 2 seconds.

Notes

realtime_capture.py does not currently write to traffic_log.csv. If you want live charts, add logging in realtime_capture.py to append rows with Source IP, Destination IP, Attack.
If ids_model.pkl is missing, run train_model.py first.