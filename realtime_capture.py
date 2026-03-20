import pandas as pd
import joblib
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# ===============================
# 1. LOAD MODEL
# ===============================
data = joblib.load("ids_model.pkl")
model = data["model"]
threshold = data["threshold"]
columns = data["columns"]

print("✅ Model loaded successfully")
print(f"Using threshold: {threshold}")

# ===============================
# 2. FEATURE EXTRACTION
# ===============================
def extract_features(packet):
    features = {}

    # Initialize all expected columns
    for col in columns:
        features[col] = 0

    try:
        features["packet_length"] = len(packet)

        if packet.haslayer(IP):
            features["ttl"] = packet[IP].ttl

        if packet.haslayer(TCP):
            features["src_port"] = packet[TCP].sport
            features["dst_port"] = packet[TCP].dport
            features["tcp_flag"] = int(packet[TCP].flags)

        elif packet.haslayer(UDP):
            features["src_port"] = packet[UDP].sport
            features["dst_port"] = packet[UDP].dport

    except:
        pass

    return features

# ===============================
# 3. PREDICTION FUNCTION
# ===============================
def predict_packet(features):
    df = pd.DataFrame([features])
    df = df.reindex(columns=columns, fill_value=0)

    proba = model.predict_proba(df)[:, 1][0]
    pred = 1 if proba > threshold else 0

    return pred, proba

# ===============================
# 4. LOGGING
# ===============================
def log_result(features, pred, proba):
    label = "ATTACK 🚨" if pred == 1 else "NORMAL ✅"

    log = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "prediction": label,
        "confidence": round(proba, 3),
        **features
    }

    print(log)

    # Save to CSV (for dashboard)
    df = pd.DataFrame([log])
    df.to_csv("live_logs.csv", mode='a', index=False, header=False)

# ===============================
# 5. PACKET HANDLER
# ===============================
def process_packet(packet):
    features = extract_features(packet)
    pred, proba = predict_packet(features)
    log_result(features, pred, proba)

# ===============================
# 6. START CAPTURE
# ===============================
print("🚀 Starting Real-Time IDS... Press Ctrl+C to stop")

sniff(prn=process_packet, store=False)