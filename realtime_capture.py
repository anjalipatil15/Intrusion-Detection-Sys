from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib
from collections import defaultdict
import time

# Load trained IDS model
model = joblib.load("ids_model.pkl")

print("Model loaded successfully")
print("Starting packet capture...\n")

# Traffic tracking memory

connection_count = defaultdict(int)
service_count = defaultdict(int)
port_scan_tracker = defaultdict(set)

# Feature Extraction

def extract_features(packet):

    protocol = "icmp"
    service = "http"
    flag = "SF"

    if packet.haslayer(TCP):
        protocol = "tcp"
        service = str(packet[TCP].dport)

    elif packet.haslayer(UDP):
        protocol = "udp"
        service = str(packet[UDP].dport)

    length = len(packet)

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # update connection counters
    connection_count[src_ip] += 1
    service_count[(src_ip, service)] += 1

    data = {
        "duration":0,
        "protocol_type":protocol,
        "service":service,
        "flag":flag,
        "src_bytes":length,
        "dst_bytes":length,
        "land":1 if src_ip == dst_ip else 0,
        "wrong_fragment":0,
        "urgent":0,
        "hot":0,
        "num_failed_logins":0,
        "logged_in":1,
        "num_compromised":0,
        "root_shell":0,
        "su_attempted":0,
        "num_root":0,
        "num_file_creations":0,
        "num_shells":0,
        "num_access_files":0,
        "num_outbound_cmds":0,
        "is_host_login":0,
        "is_guest_login":0,
        "count":connection_count[src_ip],
        "srv_count":service_count[(src_ip, service)],
        "serror_rate":0,
        "srv_serror_rate":0,
        "rerror_rate":0,
        "srv_rerror_rate":0,
        "same_srv_rate":0,
        "diff_srv_rate":0,
        "srv_diff_host_rate":0,
        "dst_host_count":connection_count[dst_ip],
        "dst_host_srv_count":service_count[(src_ip, service)],
        "dst_host_same_srv_rate":0,
        "dst_host_diff_srv_rate":0,
        "dst_host_same_src_port_rate":0,
        "dst_host_srv_diff_host_rate":0,
        "dst_host_serror_rate":0,
        "dst_host_srv_serror_rate":0,
        "dst_host_rerror_rate":0,
        "dst_host_srv_rerror_rate":0
    }

    return pd.DataFrame([data])

# Packet Processing

def process_packet(packet):

    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst

    if packet.haslayer(TCP):
        port_scan_tracker[src].add(packet[TCP].dport)

    # Detect port scan
    if len(port_scan_tracker[src]) > 20:
        print("⚠ ALERT: Possible PORT SCAN from", src)

    features = extract_features(packet)

    prediction = model.predict(features)

    print("Packet captured")
    print("Source IP:", src)
    print("Destination IP:", dst)

    if prediction[0] == 0:
        print("Prediction: Normal Traffic\n")

    elif prediction[0] == 1:
        print("⚠ ALERT: DoS Attack\n")

    elif prediction[0] == 2:
        print("⚠ ALERT: Probe Attack\n")

    elif prediction[0] == 3:
        print("⚠ ALERT: R2L Attack\n")

    elif prediction[0] == 4:
        print("⚠ ALERT: U2R Attack\n")

# Start Packet Capture

sniff(prn=process_packet, store=False)