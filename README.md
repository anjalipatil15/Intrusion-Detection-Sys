# Intrusion Detection System (IDS)

A lightweight **network intrusion detection system** built using the **NSL-KDD dataset**.
The project trains a machine learning model to detect malicious network traffic and supports **live packet monitoring** with a simple visualization dashboard.

---

# Project Structure

```
Intrusion-Detection-Sys/
│
├── dataset/
│   ├── NSL_KDD_Train.csv
│   └── NSL_KDD_Test.csv
│
├── train_model.py        # trains the IDS model
├── realtime_capture.py   # captures packets and runs predictions
├── dashboard.py          # Streamlit dashboard
├── ids_model.pkl         # trained model (generated after training)
├── traffic_log.csv       # log file used by the dashboard
├── requirements.txt
└── README.md
```

---

# Requirements

* Python **3.9 or newer**
* Required packages listed in `requirements.txt`

Windows users capturing packets may also need **Npcap** installed.

---

# Setup (Windows CMD)

Create a virtual environment:

```cmd
python -m venv .venv
```

Activate the environment:

```cmd
.\.venv\Scripts\activate
```

Install dependencies:

```cmd
pip install -r requirements.txt
```

---

# Dataset

Place the NSL-KDD dataset files inside the `dataset` folder:

```
dataset\NSL_KDD_Train.csv
dataset\NSL_KDD_Test.csv
```

---

# Train the Model

Run the training script:

```cmd
python train_model.py
```

This trains the model and generates:

```
ids_model.pkl
```

---

# Run Real-Time Detection

Start packet monitoring:

```cmd
python realtime_capture.py
```

The script captures network packets and prints alerts in the terminal when suspicious traffic is detected.

---

# Run the Dashboard

Start the visualization dashboard:

```cmd
streamlit run dashboard.py
```

Open the URL shown in the terminal (usually `http://localhost:8501`).

The dashboard reads from `traffic_log.csv` and displays basic traffic and detection activity.

---

# Quick Start

```
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt

python train_model.py
python realtime_capture.py
streamlit run dashboard.py
```

---

# Notes

* Run `train_model.py` before starting real-time detection.
* Packet capture may require running **Command Prompt as Administrator**.
* For live dashboard updates, `realtime_capture.py` can be extended to append results to `traffic_log.csv`.

---

# License

This project is provided for educational and research purposes.
