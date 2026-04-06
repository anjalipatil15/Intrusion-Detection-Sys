"""Shared binary IDS inference helpers (class order + threshold)."""
import numpy as np

# F1 tuning often picks very low thresholds on imbalanced data → almost all flows = ATTACK.
# Applied when no explicit --threshold is passed at runtime. Raise to reduce false ATTACKs.
DEFAULT_THRESHOLD_FLOOR = 0.72


def attack_probability(binary_pipeline, X):
    """P(y == 1) with 1 = malicious, matching train_model binary_label."""
    prob = binary_pipeline.predict_proba(X)
    classes = np.asarray(binary_pipeline.classes_)
    idx = np.nonzero(classes == 1)[0]
    if len(idx) != 1:
        raise ValueError(f"Expected exactly one class label 1, got classes_={classes!r}")
    return prob[:, int(idx[0])]


def resolve_threshold(saved_threshold, override):
    """Use CLI override if set; else max(saved, floor) to limit false positives."""
    if override is not None:
        return float(override)
    return max(float(saved_threshold), DEFAULT_THRESHOLD_FLOOR)