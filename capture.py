import pandas as pd
import numpy as np
import time
import random
import joblib
import os

# ===============================
# LOAD DATA + MODEL
# ===============================

df = pd.read_csv("reduced_ids_dataset.csv")
df.columns = df.columns.str.strip()

data = joblib.load("ids_model.pkl")

binary_model = data["binary_model"]
attack_model = data["attack_model"]
threshold = data["threshold"]
columns = data["columns"]
label_encoder = data["label_encoder"]

print("Simulation running...\n")

# ===============================
# HELPERS
# ===============================

def perturb(row):
    """Add slight noise to simulate real traffic"""
    row = row.copy()

    for col in row.index:
        if isinstance(row[col], (int, float)):
            noise = np.random.normal(0, 0.05)
            row[col] = row[col] * (1 + noise)

    return row

# ===============================
# SIMULATION CONTROL
# ===============================

attack_mode = False
attack_counter = 0

attack_types = ["DOS", "PORTSCAN", "WEBATTACK"]
attack_weights = [0.6, 0.3, 0.1]

# ===============================
# STREAM LOOP
# ===============================

while True:

    # trigger attack burst (rare)
    if not attack_mode and random.random() < 0.02:
        attack_mode = True
        attack_counter = random.randint(3, 6)

    # ===============================
    # SELECT SAMPLE
    # ===============================

    if attack_mode:
        chosen_attack = random.choices(attack_types, weights=attack_weights)[0]
        sample = df[df["Label"] == chosen_attack].sample(1)

        attack_counter -= 1
        if attack_counter <= 0:
            attack_mode = False

    else:
        # mostly normal traffic
        if random.random() < 0.95:
            sample = df[df["Label"] == "BENIGN"].sample(1)
        else:
            sample = df[df["Label"] != "BENIGN"].sample(1)

    # ===============================
    # FEATURE PROCESSING
    # ===============================

    row = sample.drop(columns=["Label"]).iloc[0]
    row = perturb(row)

    X_live = pd.DataFrame([row])
    X_live = X_live.reindex(columns=columns, fill_value=0)

    # ===============================
    # STAGE 1: DETECTION
    # ===============================

    proba = binary_model.predict_proba(X_live)[:, 1][0]
    is_attack = int(proba > threshold)

    # ===============================
    # STAGE 2: CLASSIFICATION
    # ===============================

    if is_attack:
        attack_pred = attack_model.predict(X_live)
        attack_type = label_encoder.inverse_transform(attack_pred)[0]

        # safety check
        if attack_type in ["BENIGN", "NORMAL"]:
            attack_type = "UNKNOWN_ATTACK"
    else:
        attack_type = "NORMAL"

    # ===============================
    # LOG OUTPUT
    # ===============================

    log = {
        "time": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
        "prediction": "ATTACK" if is_attack else "NORMAL",
        "attack_type": attack_type,
        "confidence": float(round(proba, 3))
    }

    # print clean log
    print(f"{log['time']},{log['prediction']},{log['attack_type']},{log['confidence']}")

    # ===============================
    # SAVE TO CSV
    # ===============================

    file_exists = os.path.isfile("live_logs.csv")

    pd.DataFrame([log]).to_csv(
        "live_logs.csv",
        mode="a",
        index=False,
        header=not file_exists
    )

    # simulate real-time delay
    time.sleep(1)