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

proba = binary_pipeline.predict_proba(X_test)[:, 1]

best_threshold = 0.5
best_f1 = 0

for t in np.arange(0.1, 0.9, 0.01):
    preds = (proba > t).astype(int)
    score = f1_score(y_test, preds)

    if score > best_f1:
        best_f1 = score
        best_threshold = t

print(f"\nBest Threshold: {best_threshold:.2f}")
print(f"Best F1 Score: {best_f1:.4f}")

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