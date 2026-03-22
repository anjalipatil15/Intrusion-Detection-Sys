"""Append IDS log rows without losing the CSV header on empty files."""
import os

import pandas as pd


def append_log_row(path: str, row: dict, columns: list) -> None:
    """Write one row; write header if file is missing or zero-length."""
    need_header = (not os.path.isfile(path)) or os.path.getsize(path) == 0
    pd.DataFrame([row]).to_csv(
        path,
        mode="a",
        index=False,
        header=need_header,
        columns=columns,
    )
