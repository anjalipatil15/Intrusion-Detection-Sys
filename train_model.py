import argparse

import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler

from xgboost import XGBClassifier

from ids_inference import attack_probability


def parse_args():
    p = argparse.ArgumentParser(description="Train IDS binary + attack-type models")
    p.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Binary decision threshold (0–1). If omitted, pick value that maximizes F1 on the hold-out split.",
    )
    return p.parse_args()


_cli = parse_args()
if _cli.threshold is not None and not 0 <= _cli.threshold <= 1:
    raise SystemExit("--threshold must be between 0 and 1")

# ===============================
# LOAD DATA
# ===============================

df = pd.read_csv("reduced_ids_dataset.csv")

# Clean columns
df.columns = df.columns.str.strip()

# Clean values
df.replace([np.inf, -np.inf], 0, inplace=True)
df.fillna(0, inplace=True)

# Normalize labels
df["Label"] = df["Label"].str.strip().str.upper()

print("Dataset Shape:", df.shape)
print("\nOriginal Labels:")
print(df["Label"].value_counts())

# ===============================
# CREATE BINARY LABEL
# ===============================

df["binary_label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

print("\nBinary Distribution:")
print(df["binary_label"].value_counts())

# ===============================
# FEATURES
# ===============================

X = df.drop(columns=["Label", "binary_label"])
y_binary = df["binary_label"]

# ===============================
# TRAIN-TEST SPLIT (BINARY)
# ===============================

X_train, X_test, y_train, y_test = train_test_split(
    X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
)

# ===============================
# PIPELINE
# ===============================

numeric_features = X.columns.tolist()

preprocessor = ColumnTransformer(
    transformers=[
        ("num", StandardScaler(), numeric_features)
    ]
)

# ===============================
# BINARY MODEL
# ===============================

binary_model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    eval_metric="logloss",
    random_state=42
)

binary_pipeline = Pipeline([
    ("preprocessor", preprocessor),
    ("model", binary_model)
])

print("\nTraining Binary Model...")
binary_pipeline.fit(X_train, y_train)

# ===============================
# THRESHOLD OPTIMIZATION
# ===============================

proba = attack_probability(binary_pipeline, X_test)

if _cli.threshold is not None:
    best_threshold = float(_cli.threshold)
    print(f"\nUsing threshold from CLI: {best_threshold:.2f}")
else:
    # Prefer stricter cutoffs so replay/dashboard show fewer false ATTACKs.
    best_threshold = 0.65
    best_f1 = 0.0
    for t in np.arange(0.65, 0.94, 0.01):
        preds = (proba > t).astype(int)
        score = f1_score(y_test, preds)
        if score > best_f1:
            best_f1 = score
            best_threshold = t
    print(f"\nBest Threshold (F1 on hold-out, searched 0.65–0.93): {best_threshold:.2f}")
    print(f"Best F1 Score: {best_f1:.4f}")

f1_at_threshold = f1_score(y_test, (proba > best_threshold).astype(int))
print(f"F1 at saved threshold: {f1_at_threshold:.4f}")

final_preds = (proba > best_threshold).astype(int)

print("\nBinary Confusion Matrix:")
print(confusion_matrix(y_test, final_preds))

print("\nBinary Classification Report:")
print(classification_report(y_test, final_preds))

# ===============================
# ATTACK TYPE MODEL (STRICT CLEAN)
# ===============================

attack_df = df.copy()

# REMOVE ALL NON-ATTACKS
attack_df = attack_df[attack_df["Label"] != "BENIGN"]
attack_df = attack_df[attack_df["Label"] != "NORMAL"]

# OPTIONAL: remove weak/garbage class
attack_df = attack_df[attack_df["Label"] != "OTHER"]

print("\nFinal Attack Labels:")
print(attack_df["Label"].value_counts())

# ===============================
# FEATURES FOR ATTACK MODEL
# ===============================

X_attack = attack_df.drop(columns=["Label", "binary_label"])
y_attack = attack_df["Label"]

# Encode attack types
label_encoder = LabelEncoder()
y_attack_encoded = label_encoder.fit_transform(y_attack)

print("\nEncoded Classes:")
print(label_encoder.classes_)

# ===============================
# TRAIN-TEST SPLIT (ATTACK)
# ===============================

X_train_a, X_test_a, y_train_a, y_test_a = train_test_split(
    X_attack,
    y_attack_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_attack_encoded
)

# ===============================
# ATTACK MODEL
# ===============================

attack_model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    eval_metric="mlogloss",
    random_state=42
)

attack_pipeline = Pipeline([
    ("preprocessor", preprocessor),
    ("model", attack_model)
])

print("\nTraining Attack Type Model...")
attack_pipeline.fit(X_train_a, y_train_a)

# ===============================
# EVALUATION
# ===============================

preds_a = attack_pipeline.predict(X_test_a)

print("\nAttack Type Confusion Matrix:")
print(confusion_matrix(y_test_a, preds_a))

print("\nAttack Type Classification Report:")
print(classification_report(y_test_a, preds_a))

# ===============================
# SAVE EVERYTHING
# ===============================

joblib.dump({
    "binary_model": binary_pipeline,
    "attack_model": attack_pipeline,
    "threshold": best_threshold,
    "columns": X.columns.tolist(),
    "label_encoder": label_encoder
}, "ids_model.pkl")

print("\n✅ CLEAN IDS MODEL SAVED SUCCESSFULLY!")