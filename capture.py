"""
Replay flow features from the training CSV through the IDS (binary + attack-type).
Use this path for demos: feature schema always matches ids_model.pkl.
"""
import argparse
import os
import random
import time

import joblib
import numpy as np
import pandas as pd

from ids_inference import DEFAULT_THRESHOLD_FLOOR, attack_probability, resolve_threshold
from log_csv import append_log_row

LOG_COLUMNS = ["timestamp", "prediction", "attack_type", "confidence", "ground_truth"]

DEFAULT_ATTACK_TYPES = ["DOS", "PORTSCAN", "WEBATTACK"]


def perturb(row, enabled=True):
    if not enabled:
        return row.copy()
    row = row.copy()
    for col in row.index:
        if isinstance(row[col], (int, float, np.floating, np.integer)):
            noise = np.random.normal(0, 0.05)
            row[col] = row[col] * (1 + noise)
    return row


def parse_args():
    p = argparse.ArgumentParser(description="IDS live simulation via dataset replay")
    p.add_argument("--dataset", default="reduced_ids_dataset.csv", help="CSV with same schema as training")
    p.add_argument("--model", default="ids_model.pkl", help="Trained bundle from train_model.py")
    p.add_argument("--log-file", default="live_logs.csv", help="Unified log for the dashboard")
    p.add_argument("--sleep", type=float, default=1.0, help="Seconds between simulated flows")
    p.add_argument(
        "--burst-prob",
        type=float,
        default=0.0,
        help="Optional: per-tick probability of a short multi-flow attack burst (0 = off)",
    )
    p.add_argument(
        "--benign-ratio",
        type=float,
        default=0.8,
        help="Fraction of traffic that is BENIGN; rest is sampled from attack classes only (0–1)",
    )
    p.add_argument("--burst-min", type=int, default=3, help="Minimum flows in one attack burst")
    p.add_argument("--burst-max", type=int, default=6, help="Maximum flows in one attack burst")
    p.add_argument("--no-perturb", action="store_true", help="Disable Gaussian noise on features")
    p.add_argument(
        "--log-ground-truth",
        action="store_true",
        help="Append CSV column ground_truth (true row label) for validation",
    )
    p.add_argument("--reset-log", action="store_true", help="Delete log file before starting")
    p.add_argument(
        "--threshold",
        type=float,
        default=None,
        help=(
            f"Base cutoff: P(attack) must exceed this (0–1). Default: max(pickle, {DEFAULT_THRESHOLD_FLOOR:.2f})"
        ),
    )
    p.add_argument(
        "--attack-margin",
        type=float,
        default=0.0,
        help="Added to threshold for the real cutoff (e.g. 0.05 with --threshold 0.8 => 0.85). Reduces false ATTACKs.",
    )
    p.add_argument(
        "--consecutive-attacks",
        type=int,
        default=1,
        dest="consecutive_attacks",
        help="Require this many flows in a row above the cutoff before logging ATTACK (debounce).",
    )
    p.add_argument(
        "--alerts",
        action="store_true",
        help="Append each confirmed ATTACK row to --alerts-file (for dashboard / triage).",
    )
    p.add_argument("--alerts-file", default="alerts.csv", help="Output path when --alerts is set")
    p.add_argument(
        "--alert-beep",
        action="store_true",
        help="Terminal beep (\\a) on each confirmed ATTACK when --alerts is set",
    )
    p.add_argument(
        "--reset-alerts",
        action="store_true",
        help="Delete alerts file before starting (with --alerts)",
    )
    return p.parse_args()


def main():
    args = parse_args()
    if not 0 <= args.benign_ratio <= 1:
        raise SystemExit("--benign-ratio must be between 0 and 1")
    if not 0 <= args.burst_prob <= 1:
        raise SystemExit("--burst-prob must be between 0 and 1")
    if args.threshold is not None and not 0 <= args.threshold <= 1:
        raise SystemExit("--threshold must be between 0 and 1")
    if args.attack_margin < 0:
        raise SystemExit("--attack-margin must be >= 0")
    if args.consecutive_attacks < 1:
        raise SystemExit("--consecutive-attacks must be >= 1")

    df = pd.read_csv(args.dataset)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], 0, inplace=True)
    df.fillna(0, inplace=True)
    df["Label"] = df["Label"].str.strip().str.upper()

    data = joblib.load(args.model)
    binary_model = data["binary_model"]
    attack_model = data["attack_model"]
    saved_t = data["threshold"]
    threshold = resolve_threshold(saved_t, args.threshold)
    cutoff = min(threshold + args.attack_margin, 1.0)
    if cutoff <= 0 or cutoff > 1:
        raise SystemExit("Invalid effective cutoff (threshold + attack-margin)")
    columns = data["columns"]
    label_encoder = data["label_encoder"]

    attack_types = [a for a in DEFAULT_ATTACK_TYPES if a in set(df["Label"].unique())]
    if not attack_types:
        raise SystemExit(
            "No default attack labels found in dataset. "
            f"Have: {sorted(df['Label'].unique().tolist())}"
        )

    attack_weights = [0.6, 0.3, 0.1][: len(attack_types)]
    if len(attack_weights) < len(attack_types):
        attack_weights = [1.0 / len(attack_types)] * len(attack_types)

    if args.reset_log and os.path.isfile(args.log_file):
        os.remove(args.log_file)
    if args.alerts and args.reset_alerts and os.path.isfile(args.alerts_file):
        os.remove(args.alerts_file)

    use_perturb = not args.no_perturb
    log_cols = LOG_COLUMNS if args.log_ground_truth else LOG_COLUMNS[:-1]

    print("IDS replay running (Ctrl+C to stop)")
    print(
        f"  log: {args.log_file}  sleep: {args.sleep}s  "
        f"benign_ratio: {args.benign_ratio}  burst_prob: {args.burst_prob}  "
        f"threshold(base): {threshold}  cutoff: {cutoff}  "
        f"consecutive: {args.consecutive_attacks}  "
        f"(pickle: {saved_t})"
    )
    print(f"  attack_types: {attack_types}")
    if args.alerts:
        print(f"  alerts -> {args.alerts_file}")
    print()

    attack_mode = False
    attack_counter = 0
    raw_streak = 0

    while True:
        if not attack_mode and random.random() < args.burst_prob:
            attack_mode = True
            attack_counter = random.randint(args.burst_min, args.burst_max)

        if attack_mode:
            chosen = random.choices(attack_types, weights=attack_weights, k=1)[0]
            pool = df[df["Label"] == chosen]
            if pool.empty:
                attack_mode = False
                time.sleep(args.sleep)
                continue
            sample = pool.sample(1)
            attack_counter -= 1
            if attack_counter <= 0:
                attack_mode = False
        else:
            if random.random() < args.benign_ratio:
                pool = df[df["Label"] == "BENIGN"]
                if pool.empty:
                    pool = df
                sample = pool.sample(1)
            else:
                chosen = random.choices(attack_types, weights=attack_weights, k=1)[0]
                pool = df[df["Label"] == chosen]
                if pool.empty:
                    pool = df[df["Label"].isin(attack_types)]
                if pool.empty:
                    pool = df[df["Label"] != "BENIGN"]
                if pool.empty:
                    pool = df
                sample = pool.sample(1)

        true_label = sample["Label"].iloc[0]
        row = sample.drop(columns=["Label"]).iloc[0]
        row = perturb(row, enabled=use_perturb)

        X_live = pd.DataFrame([row]).reindex(columns=columns, fill_value=0)

        proba = float(attack_probability(binary_model, X_live)[0])
        raw_fire = proba > cutoff
        if raw_fire:
            raw_streak += 1
        else:
            raw_streak = 0
        is_attack = int(raw_streak >= args.consecutive_attacks)

        if is_attack:
            attack_pred = attack_model.predict(X_live)
            attack_type = label_encoder.inverse_transform(attack_pred)[0]
            if attack_type in ("BENIGN", "NORMAL"):
                attack_type = "UNKNOWN_ATTACK"
        else:
            attack_type = "NORMAL"

        log = {
            "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
            "prediction": "ATTACK" if is_attack else "NORMAL",
            "attack_type": attack_type,
            "confidence": round(proba, 3),
        }
        if args.log_ground_truth:
            log["ground_truth"] = true_label

        print(
            f"{log['timestamp']},{log['prediction']},{log['attack_type']},{log['confidence']}"
            + (f",{log['ground_truth']}" if args.log_ground_truth else "")
        )

        append_log_row(args.log_file, log, log_cols)

        if args.alerts and is_attack:
            alert_row = {
                "timestamp": log["timestamp"],
                "attack_type": attack_type,
                "confidence": log["confidence"],
                "cutoff": round(cutoff, 4),
            }
            acols = ["timestamp", "attack_type", "confidence", "cutoff"]
            if args.log_ground_truth:
                alert_row["ground_truth"] = true_label
                acols.append("ground_truth")
            append_log_row(args.alerts_file, alert_row, acols)
            if args.alert_beep:
                print("\a", end="", flush=True)

        time.sleep(args.sleep)


if __name__ == "__main__":
    main()
