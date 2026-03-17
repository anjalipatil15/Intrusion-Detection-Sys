import pandas as pd
import joblib
import random
import time

model = joblib.load("ids_model.pkl")

attacks = ["Normal", "DoS", "Probe"]

def generate_flow():

    attack = random.choice(attacks)

    if attack == "Normal":
        data = {
            "duration": random.uniform(1,3),
            "protocol_type": "tcp",
            "service": "http",
            "flag": "SF",
            "src_bytes": random.randint(500,2000),
            "dst_bytes": random.randint(1000,5000),
            "land":0,
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
            "count":1,
            "srv_count":1,
            "serror_rate":0,
            "srv_serror_rate":0,
            "rerror_rate":0,
            "srv_rerror_rate":0,
            "same_srv_rate":1,
            "diff_srv_rate":0,
            "srv_diff_host_rate":0,
            "dst_host_count":1,
            "dst_host_srv_count":1,
            "dst_host_same_srv_rate":1,
            "dst_host_diff_srv_rate":0,
            "dst_host_same_src_port_rate":1,
            "dst_host_srv_diff_host_rate":0,
            "dst_host_serror_rate":0,
            "dst_host_srv_serror_rate":0,
            "dst_host_rerror_rate":0,
            "dst_host_srv_rerror_rate":0
        }

    elif attack == "DoS":

        data = {
            "duration":0,
            "protocol_type":"tcp",
            "service":"http",
            "flag":"S0",
            "src_bytes":0,
            "dst_bytes":0,
            "land":0,
            "wrong_fragment":0,
            "urgent":0,
            "hot":0,
            "num_failed_logins":0,
            "logged_in":0,
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
            "count":80,
            "srv_count":80,
            "serror_rate":1,
            "srv_serror_rate":1,
            "rerror_rate":0,
            "srv_rerror_rate":0,
            "same_srv_rate":1,
            "diff_srv_rate":0,
            "srv_diff_host_rate":0,
            "dst_host_count":255,
            "dst_host_srv_count":255,
            "dst_host_same_srv_rate":1,
            "dst_host_diff_srv_rate":0,
            "dst_host_same_src_port_rate":0,
            "dst_host_srv_diff_host_rate":0,
            "dst_host_serror_rate":1,
            "dst_host_srv_serror_rate":1,
            "dst_host_rerror_rate":0,
            "dst_host_srv_rerror_rate":0
        }

    else:  # Probe

        data = {
            "duration":0.5,
            "protocol_type":"tcp",
            "service":"http",
            "flag":"SF",
            "src_bytes":100,
            "dst_bytes":50,
            "land":0,
            "wrong_fragment":0,
            "urgent":0,
            "hot":0,
            "num_failed_logins":0,
            "logged_in":0,
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
            "count":20,
            "srv_count":5,
            "serror_rate":0,
            "srv_serror_rate":0,
            "rerror_rate":1,
            "srv_rerror_rate":1,
            "same_srv_rate":0.3,
            "diff_srv_rate":0.7,
            "srv_diff_host_rate":0.5,
            "dst_host_count":50,
            "dst_host_srv_count":10,
            "dst_host_same_srv_rate":0.2,
            "dst_host_diff_srv_rate":0.8,
            "dst_host_same_src_port_rate":0.2,
            "dst_host_srv_diff_host_rate":0.5,
            "dst_host_serror_rate":0,
            "dst_host_srv_serror_rate":0,
            "dst_host_rerror_rate":1,
            "dst_host_srv_rerror_rate":1
        }

    return data


while True:

    flow = generate_flow()

    df = pd.DataFrame([flow])

    print("\nGenerated Flow:")
    print(df)
    prediction = model.predict(df)[0]

    attack_label = ["Normal","DoS","Probe","R2L","U2R"][prediction]

    print("Model Prediction:", attack_label)

    time.sleep(1)