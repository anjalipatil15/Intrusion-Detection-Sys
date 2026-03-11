import pandas as pd
import numpy as np

from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

from sklearn.feature_selection import RFE
from sklearn.ensemble import RandomForestClassifier, VotingClassifier

from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC

from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score


# ==============================
# 1. Load Dataset
# ==============================

train_url = "..\\ids\\dataset\\NSL_KDD_Train.csv"
test_url = "..\\ids\\dataset\\NSL_KDD_Test.csv"

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
"dst_host_srv_rerror_rate","label"
]

train = pd.read_csv(train_url, names=columns)
test = pd.read_csv(test_url, names=columns)

print("Training Shape:", train.shape)
print("Test Shape:", test.shape)


# ==============================
# 2. Label Mapping
# ==============================

label_map = {
'normal':0,

# DoS
'neptune':1,'back':1,'land':1,'pod':1,'smurf':1,'teardrop':1,
'mailbomb':1,'apache2':1,'processtable':1,'udpstorm':1,'worm':1,

# Probe
'ipsweep':2,'nmap':2,'portsweep':2,'satan':2,'mscan':2,'saint':2,

# R2L
'ftp_write':3,'guess_passwd':3,'imap':3,'multihop':3,'phf':3,'spy':3,
'warezclient':3,'warezmaster':3,'sendmail':3,'named':3,
'snmpgetattack':3,'snmpguess':3,'xlock':3,'xsnoop':3,'httptunnel':3,

# U2R
'buffer_overflow':4,'loadmodule':4,'perl':4,'rootkit':4,
'ps':4,'sqlattack':4,'xterm':4
}

train["label"] = train["label"].map(label_map)
test["label"] = test["label"].map(label_map)


# ==============================
# 3. Split Features / Labels
# ==============================

X_train = train.drop("label", axis=1)
y_train = train["label"]

X_test = test.drop("label", axis=1)
y_test = test["label"]


# ==============================
# 4. Preprocessing
# ==============================

categorical_cols = ["protocol_type","service","flag"]
numeric_cols = [c for c in X_train.columns if c not in categorical_cols]

preprocessor = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
        ("num", StandardScaler(), numeric_cols)
    ]
)

# ==============================
# 5. Feature Selection
# ==============================

rf = RandomForestClassifier(n_estimators=50, random_state=42)

feature_selector = RFE(
    estimator=rf,
    n_features_to_select=13
)

# ==============================
# 6. Models
# ==============================

rf_model = RandomForestClassifier(n_estimators=100)
knn_model = KNeighborsClassifier()
svm_model = SVC(kernel="linear")

voting_model = VotingClassifier(
    estimators=[
        ("rf", rf_model),
        ("knn", knn_model),
        ("svm", svm_model)
    ],
    voting="hard"
)


# ==============================
# 7. Pipeline
# ==============================

pipeline = Pipeline([
    ("preprocess", preprocessor),
    ("feature_select", feature_selector),
    ("model", voting_model)
])

# ==============================
# 8. Train Model
# ==============================

pipeline.fit(X_train, y_train)

# ==============================
# 9. Predictions
# ==============================

y_pred = pipeline.predict(X_test)

# ==============================
# 10. Evaluation
# ==============================

print("\nConfusion Matrix")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report")
print(classification_report(y_test, y_pred))

import joblib

joblib.dump(pipeline, "ids_model.pkl")

print("Model saved successfully")