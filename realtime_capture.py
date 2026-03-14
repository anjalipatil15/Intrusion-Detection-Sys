from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib
from collections import defaultdict
import csv
import time

# Load trained pipeline
model = joblib.load("ids_model.pkl")

print("Model loaded successfully")
print("Starting packet capture...\n")

# Traffic memory
connection_count = defaultdict(int)
service_count = defaultdict(int)
port_scan_tracker = defaultdict(set)

# NSL-KDD column order
columns = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
"root_shell","su_attempted","num_root","num_file_creations","num_shells",
"num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
"count","srv_count","serror_rate","srv_serror_rate","rerror_rate",
"srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate",
"dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
"dst_host_diff_srv_rate","dst_host_same_src_port_rate",
"dst_host_srv_diff_host_rate","dst_host_serror_rate",
"dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate"
]

# Log attacks for dashboard
def log_attack(src, dst, attack):
    with open("traffic_log.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([time.time(), src, dst, attack])

# Feature extraction
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

    # update counters
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

    return pd.DataFrame([data], columns=columns)

# Packet processing
def process_packet(packet):

    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst

    # Port scan detection
    if packet.haslayer(TCP):
        port_scan_tracker[src].add(packet[TCP].dport)

    if len(port_scan_tracker[src]) > 20:
        print("\n⚠ ALERT: Possible PORT SCAN from", src)
        log_attack(src, dst, "Port Scan")

    try:

        features = extract_features(packet)

        prediction = model.predict(features)

        if prediction[0] != 0:

            print("\n⚠ ALERT DETECTED")
            print("Source IP:", src)
            print("Destination IP:", dst)

            if prediction[0] == 1:
                print("Attack Type: DoS\n")
                log_attack(src, dst, "DoS")

            elif prediction[0] == 2:
                print("Attack Type: Probe\n")
                log_attack(src, dst, "Probe")

            elif prediction[0] == 3:
                print("Attack Type: R2L\n")
                log_attack(src, dst, "R2L")

            elif prediction[0] == 4:
                print("Attack Type: U2R\n")
                log_attack(src, dst, "U2R")

    except Exception as e:
        print("Prediction error:", e)

# Start capture
sniff(filter="ip", prn=process_packet, store=False)