import os
import time
from typing import Optional

import numpy as np
import pandas as pd
import streamlit as st

LOG_FILE = "live_logs.csv"
ALERTS_FILE = "alerts.csv"
REFRESH_SECONDS = 2

EXPECTED_COLS = ["timestamp", "prediction", "attack_type", "confidence"]


def normalize_prediction(series: pd.Series) -> pd.Series:
    """Map log values to ATTACK vs NORMAL."""
    out = []
    for x in series:
        if pd.isna(x):
            out.append("NORMAL")
            continue
        if isinstance(x, bool):
            out.append("NORMAL")
            continue
        if isinstance(x, (int, float, np.integer, np.floating)):
            out.append("ATTACK" if int(x) == 1 else "NORMAL")
            continue
        s = str(x).strip().upper()
        if s.startswith("ATTACK") or s == "1":
            out.append("ATTACK")
        else:
            out.append("NORMAL")
    return pd.Series(out, index=series.index, dtype="object")


def _read_csv_raw(path: str) -> pd.DataFrame:
    read_kw = {"encoding": "utf-8"}
    try:
        try:
            return pd.read_csv(path, on_bad_lines="skip", **read_kw)
        except TypeError:
            try:
                return pd.read_csv(path, error_bad_lines=False, warn_bad_lines=False, **read_kw)
            except TypeError:
                return pd.read_csv(path, **read_kw)
    except (pd.errors.EmptyDataError, pd.errors.ParserError):
        try:
            try:
                return pd.read_csv(path, engine="python", on_bad_lines="skip", **read_kw)
            except TypeError:
                return pd.read_csv(path, engine="python", **read_kw)
        except Exception:
            return pd.DataFrame()


def _prediction_column_trustworthy(s: pd.Series) -> bool:
    """False when 'prediction' is misaligned (e.g. holds floats / timestamps)."""
    s = s.dropna()
    if len(s) == 0:
        return False
    sample = s.head(50).astype(str).str.strip()
    floatish = 0
    for v in sample:
        try:
            float(v)
            if v.lower() not in ("0", "1", "0.0", "1.0"):
                floatish += 1
        except ValueError:
            pass
    if floatish / len(sample) > 0.35:
        return False
    u = sample.str.upper()
    ok = u.isin(["ATTACK", "NORMAL"]) | u.str.startswith("ATTACK")
    return bool(ok.mean() >= 0.25)


def _repair_eight_column_mess(df: pd.DataFrame) -> Optional[pd.DataFrame]:
    """First row was data but became header; real names stuck as last 4 columns."""
    cols = [str(c).strip() for c in df.columns]
    if len(cols) < 8:
        return None
    tail = [c.lower() for c in cols[-4:]]
    if tail != ["timestamp", "prediction", "attack_type", "confidence"]:
        return None
    out = df.iloc[:, :4].copy()
    out.columns = EXPECTED_COLS
    return out


def _coerce_from_headerless(raw: pd.DataFrame) -> pd.DataFrame:
    if raw.shape[0] == 0 or raw.shape[1] < 4:
        return pd.DataFrame(columns=EXPECTED_COLS)

    c0 = str(raw.iloc[0, 0]).strip().lower()
    if c0 == "timestamp":
        n = min(4, raw.shape[1])
        hdr = raw.iloc[0, :n].astype(str).str.strip().tolist()
        body = raw.iloc[1:, :n].copy()
        body.columns = hdr
        if [h.lower() for h in hdr[:4]] == EXPECTED_COLS:
            body.columns = EXPECTED_COLS[:n]
        return _finish_log_df(body)

    for i in range(len(raw)):
        if raw.shape[1] < 4:
            break
        p = str(raw.iloc[i, 1]).strip().upper()
        if p in ("ATTACK", "NORMAL") or (p.startswith("ATTACK") and len(p) < 24):
            blk = raw.iloc[i:, :4].copy()
            blk.columns = EXPECTED_COLS
            return _finish_log_df(blk)

    return pd.DataFrame(columns=EXPECTED_COLS)


def _finish_log_df(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    for c in EXPECTED_COLS:
        if c not in df.columns:
            df[c] = pd.NA
    ts = df["timestamp"].astype(str).str.strip().str.lower()
    pr = df["prediction"].astype(str).str.strip().str.upper()
    mask_header = ts.eq("timestamp") & pr.eq("PREDICTION")
    df = df.loc[~mask_header].reset_index(drop=True)
    keep = [c for c in df.columns if c in EXPECTED_COLS]
    if "ground_truth" in df.columns:
        keep.append("ground_truth")
    return df[keep]


def load_log(path: str) -> pd.DataFrame:
    if not os.path.isfile(path):
        return pd.DataFrame(columns=EXPECTED_COLS)

    df = _read_csv_raw(path)
    df.columns = df.columns.astype(str).str.strip()

    if df.shape[0] == 0 and df.shape[1] == 0:
        return pd.DataFrame(columns=EXPECTED_COLS)

    fixed = _repair_eight_column_mess(df)
    if fixed is not None:
        df = fixed

    if "prediction" in df.columns and _prediction_column_trustworthy(df["prediction"]):
        return _finish_log_df(df)

    try:
        try:
            raw = pd.read_csv(path, header=None, encoding="utf-8", engine="python")
        except TypeError:
            raw = pd.read_csv(path, header=None, encoding="utf-8", engine="python", on_bad_lines="skip")
    except Exception:
        return _finish_log_df(df) if "prediction" in df.columns else pd.DataFrame(columns=EXPECTED_COLS)

    return _coerce_from_headerless(raw)


def load_alerts(path: str) -> pd.DataFrame:
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return pd.DataFrame()
    try:
        a = pd.read_csv(path, encoding="utf-8", on_bad_lines="skip")
    except TypeError:
        a = pd.read_csv(path, encoding="utf-8")
    except Exception:
        return pd.DataFrame()
    a.columns = a.columns.astype(str).str.strip()
    return a


def safe_bar_chart(counts: pd.Series) -> None:
    if counts.empty:
        st.caption("No data for this chart.")
        return
    chart = counts.reset_index()
    chart.columns = ["category", "count"]
    chart["category"] = chart["category"].astype(str)
    for kwargs in (
        {"x": "category", "y": "count", "height": 280},
        {"x": "category", "y": "count"},
        {},
    ):
        try:
            if kwargs:
                st.bar_chart(chart, **kwargs)
            else:
                st.bar_chart(chart.set_index("category")[["count"]])
            return
        except TypeError:
            continue


def render_alerts_panel() -> None:
    st.subheader("Alerts")
    st.caption(
        f"Confirmed ATTACKs from `python capture.py --alerts` → **{ALERTS_FILE}**. "
        "Uses the same debounced ATTACK decision as the main log (margin + consecutive)."
    )
    alerts_df = load_alerts(ALERTS_FILE)
    if alerts_df.empty:
        st.write(
            "No alert rows yet. Example: `python capture.py --threshold 0.8 "
            "--attack-margin 0.05 --consecutive-attacks 2 --alerts`"
        )
        return
    c4, c5 = st.columns(2)
    c4.metric("Alert events", len(alerts_df))
    try:
        last_a = str(alerts_df["timestamp"].dropna().astype(str).iloc[-1])
    except Exception:
        last_a = "—"
    c5.metric("Last alert", last_a)
    try:
        st.dataframe(alerts_df.tail(75), use_container_width=True)
    except TypeError:
        st.dataframe(alerts_df.tail(75))


def render_dashboard() -> None:
    df = load_log(LOG_FILE)

    if df.empty:
        st.info(
            f"No rows in **{LOG_FILE}** yet. Run `python capture.py` in another terminal."
        )
    else:
        for col in EXPECTED_COLS:
            if col not in df.columns:
                df[col] = pd.NA

        pred_clean = normalize_prediction(df["prediction"])
        attacks = df.loc[pred_clean == "ATTACK"].copy()

        display_cols = [c for c in EXPECTED_COLS if c in df.columns]
        if "ground_truth" in df.columns:
            display_cols.append("ground_truth")

        c1, c2, c3 = st.columns(3)
        c1.metric("Events logged", len(df))
        c2.metric("Flagged ATTACK", len(attacks))
        try:
            last_ts = df["timestamp"].dropna().astype(str).iloc[-1]
        except (IndexError, KeyError):
            last_ts = "—"
        c3.metric("Last event", str(last_ts))

        st.subheader("Recent events")
        try:
            st.dataframe(df[display_cols].tail(100), use_container_width=True)
        except TypeError:
            st.dataframe(df[display_cols].tail(100))

        st.subheader("Prediction distribution")
        safe_bar_chart(pred_clean.value_counts())

        st.subheader("Attack type (flagged ATTACK only)")
        st.caption("Subtype counts use only rows where prediction is ATTACK.")
        if attacks.empty:
            st.write("No ATTACK predictions in the log yet.")
        else:
            at = attacks["attack_type"]
            blank = at.isna() | (at.astype(str).str.strip().isin(("", "nan", "None")))
            display_type = at.where(~blank, "UNKNOWN").astype(str).str.strip()
            safe_bar_chart(display_type.value_counts())

        if "ground_truth" in df.columns and df["ground_truth"].notna().any():
            st.subheader("Ground truth (replay validation)")
            safe_bar_chart(df["ground_truth"].astype(str).value_counts())

    render_alerts_panel()


st.set_page_config(page_title="IDS Dashboard", layout="wide")
st.title("Intrusion Detection System")

_fragment = getattr(st, "fragment", None)
if _fragment is not None:
    @_fragment(run_every=REFRESH_SECONDS)
    def _auto() -> None:
        render_dashboard()

    _auto()
else:
    render_dashboard()
    time.sleep(REFRESH_SECONDS)
    if hasattr(st, "rerun"):
        st.rerun()
    else:
        st.experimental_rerun()
