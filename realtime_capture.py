from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib
import time
import csv

model = joblib.load("ids_model.pkl")

print("Model loaded")
print("Starting flow capture...\n")

flows = {}

FLOW_TIMEOUT = 2

def get_flow_key(packet):

    src = packet[IP].src
    dst = packet[IP].dst

    sport = 0
    dport = 0
    proto = "icmp"

    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        proto = "tcp"

    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        proto = "udp"

    return (src, dst, sport, dport, proto)


def update_flow(packet):

    key = get_flow_key(packet)
    length = len(packet)
    now = time.time()

    if key not in flows:
        flows[key] = {
            "start": now,
            "last": now,
            "src_bytes": 0,
            "dst_bytes": 0,
            "packets": 0
        }

    flow = flows[key]

    flow["packets"] += 1
    flow["last"] = now

    flow["src_bytes"] += length


def check_finished_flows():

    now = time.time()

    finished = []

    for key, flow in flows.items():

        if now - flow["last"] > FLOW_TIMEOUT:
            finished.append(key)

    for key in finished:

        flow = flows.pop(key)

        duration = flow["last"] - flow["start"]

        src, dst, sport, dport, proto = key

        service = str(dport)

        data = {
            "duration": duration,
            "protocol_type": proto,
            "service": service,
            "flag": "SF",
            "src_bytes": flow["src_bytes"],
            "dst_bytes": flow["dst_bytes"],
            "land": 1 if src == dst else 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 1,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": 1,
            "srv_count": 1,
            "serror_rate": 0,
            "srv_serror_rate": 0,
            "rerror_rate": 0,
            "srv_rerror_rate": 0,
            "same_srv_rate": 0,
            "diff_srv_rate": 0,
            "srv_diff_host_rate": 0,
            "dst_host_count": 1,
            "dst_host_srv_count": 1,
            "dst_host_same_srv_rate": 0,
            "dst_host_diff_srv_rate": 0,
            "dst_host_same_src_port_rate": 0,
            "dst_host_srv_diff_host_rate": 0,
            "dst_host_serror_rate": 0,
            "dst_host_srv_serror_rate": 0,
            "dst_host_rerror_rate": 0,
            "dst_host_srv_rerror_rate": 0
        }

        df = pd.DataFrame([data])

        prediction = model.predict(df)[0]

        attack = ["Normal","DoS","Probe","R2L","U2R"][prediction]

        print("Connection:", src, "→", dst, "|", attack)

        with open("traffic_log.csv","a",newline="") as f:
            writer = csv.writer(f)
            writer.writerow([time.time(),src,dst,attack])


def process_packet(packet):

    if not packet.haslayer(IP):
        return

    update_flow(packet)

    check_finished_flows()


sniff(filter="ip", prn=process_packet, store=False)